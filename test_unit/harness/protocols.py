"""Per-protocol test drivers. Each connects account A (primary + variants),
runs the shared check suite while A stays up, then reconnects account B for
client-to-client (same inbound) and cross-inbound (peer protocol) ping tests.
"""
from __future__ import annotations

import threading
import time

from . import abort
from . import checks
from . import server_setup
from . import traffic
from .clients import openvpn as ovpn
from .clients import l2tp as l2tp_mod
from .clients import pptp as pptp_mod
from .clients import openconnect as oc_mod
from .clients import sstp as sstp_mod
from .clients import ikev2 as ikev2_mod
from .clients import wgc as wgc_mod
from .clients import awg as awg_mod
from .clients import gre as gre_mod
from .clients import ssh as ssh_mod
from .clients import anytls as anytls_mod
from .clients import tuic as tuic_mod
from .clients import naive as naive_mod
from .clients import xraytun as xraytun_mod
from .clients.base import Client
from .model import Phase, SubTest, Status
from .model import (PHASE_OPENVPN, PHASE_L2TP, PHASE_PPTP, PHASE_OPENCONNECT,
                    PHASE_SSTP, PHASE_WGC, PHASE_AWG, PHASE_GRE, PHASE_SSH, PHASE_SSH_UDP,
                    PHASE_ANYTLS, PHASE_TUIC, PHASE_NAIVE,
                    IKEV2_PHASE_BY_MODE)

# The Xray-NATIVE proxy protocols. Grouped because every "does this apply?" decision
# below is the same for all three: xray terminates them itself, so they hand out no
# client address and own no IP block. Everything that reads a tunnel address
# (client-to-client, cross-inbound, per-device block IPs) is inapplicable, while
# everything that reads the account (routing by email, usage, multiplier, termination)
# is not just applicable but tested here for the first time in this harness.
XRAY_NATIVE = ("anytls", "tuic", "naive")

# Grace for a client edit to land. telemt itself is NOT restarted (the panel rewrites
# config.toml and telemt picks it up via inotify), but a client edit also flags Xray
# for restart, and telemt egresses THROUGH Xray's socks inbound: so this must cover
# config write -> inotify -> apply AND Xray's @every 1s restart cron plus its startup.
# Generous on purpose: too short reads as "the toggle was ignored", which is the exact
# bug this phase detects, and a false FAIL there is worse than a slow test.
MTPROTO_RELOAD_WAIT = 8.0

# cross-inbound peer: X's cross test pings a client on peer[X]'s inbound. ssh, anytls,
# tuic and naive have no entry: their cross-inbound is recorded NA (a relay/proxy has no
# client tunnel address to ping), so PEER[…] is never read for them.
PEER = {"openvpn": "l2tp", "l2tp": "pptp", "pptp": "openvpn",
        "openconnect": "openvpn", "sstp": "openvpn", "ikev2": "openvpn",
        "wg-c": "openvpn", "awg": "openvpn", "gre": "openvpn"}
# Non-ikev2 protocols map straight to their phase. ikev2 is split per auth mode
# (IKEV2_PHASE_BY_MODE), resolved inside run() from its `mode` arg.
PHASE = {"openvpn": PHASE_OPENVPN, "l2tp": PHASE_L2TP, "pptp": PHASE_PPTP,
         "openconnect": PHASE_OPENCONNECT, "sstp": PHASE_SSTP, "wg-c": PHASE_WGC,
         "awg": PHASE_AWG, "gre": PHASE_GRE, "ssh": PHASE_SSH,
         "anytls": PHASE_ANYTLS, "tuic": PHASE_TUIC, "naive": PHASE_NAIVE}

# Connect variant used when dialing the SECOND same-protocol inbound (TEST 1,
# _multi_inbound_check): l2tp uses RAW (the client's IPsec config is pinned to the
# primary's 17/1701, so a 2nd l2tp inbound is exercised over raw L2TP), openvpn
# udp/new, pptp has no variant. sstp/ikev2 have no variant (single-variant protocols).
_SECOND_VARIANT = {"openvpn": ("udp", "new"), "l2tp": "raw", "pptp": None,
                   "openconnect": "dtls", "sstp": None, "ikev2": None,
                   "wg-c": None, "awg": None, "gre": None, "ssh": None,
                   # single-variant: the dial is fully described by the inbound (one
                   # transport, one TLS config). tuic's two UDP relay modes are NOT a
                   # connect variant: they are exercised by the udp subtests, which
                   # re-dial with each mode against the SAME inbound.
                   "anytls": None, "tuic": None, "naive": None}


def _connect(client: Client, sc, proto: str, which: str, variant=None, ib=None):
    # `ib` overrides the setup inbound (used to dial a SECOND same-protocol inbound
    # built at runtime); default keeps every existing caller on sc.inbounds[proto].
    if ib is None:
        ib = sc.inbounds[proto]
    if proto == "openvpn":
        transport, cipher = variant or ("udp", "new")
        return ovpn.connect(client, ib, which, transport, cipher, sc.server_ip)
    if proto == "l2tp":
        return l2tp_mod.connect(client, ib, which, ipsec=(variant != "raw"),
                                server_ip=sc.server_ip)
    if proto == "pptp":
        return pptp_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "openconnect":
        return oc_mod.connect(client, ib, which, variant=variant or "dtls",
                              server_ip=sc.server_ip)
    if proto == "sstp":
        return sstp_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "ikev2":
        return ikev2_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "wg-c":
        return wgc_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "awg":
        return awg_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "gre":
        # `variant` carries the encapsulation mode (raw / ipsec / fou) rather than a
        # transport pair; the mode sub-tests pass it explicitly.
        return gre_mod.connect(client, ib, which, server_ip=sc.server_ip,
                               mode=variant or "raw")
    if proto == "ssh":
        return ssh_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "anytls":
        return anytls_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "tuic":
        # `variant` carries the UDP relay mode ("native" | "quic") when the udp subtests
        # dial it explicitly; every other caller passes None and gets the default the
        # panel's own share link advertises.
        if variant:
            return tuic_mod.connect_mode(client, ib, which, sc.server_ip, variant)
        return tuic_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "naive":
        return naive_mod.connect(client, ib, which, server_ip=sc.server_ip)
    raise ValueError(proto)


def _disconnect(client: Client, proto: str):
    {"openvpn": ovpn.disconnect,
     "l2tp": l2tp_mod.disconnect,
     "pptp": pptp_mod.disconnect,
     "openconnect": oc_mod.disconnect,
     "sstp": sstp_mod.disconnect,
     "ikev2": ikev2_mod.disconnect,
     "wg-c": wgc_mod.disconnect,
     "awg": awg_mod.disconnect,
     "gre": gre_mod.disconnect,
     "ssh": ssh_mod.disconnect,
     "anytls": anytls_mod.disconnect,
     "tuic": tuic_mod.disconnect,
     "naive": naive_mod.disconnect}[proto](client)


def _variants(proto: str):
    """(label, variant, is_primary) connect variants for a protocol."""
    if proto == "openvpn":
        return [
            ("connect-udp-new", ("udp", "new"), True),
            ("connect-udp-old", ("udp", "old"), False),
            ("connect-tcp-new", ("tcp", "new"), False),
            ("connect-tcp-old", ("tcp", "old"), False),
        ]
    if proto == "l2tp":
        return [
            ("connect-ipsec", "ipsec", True),
            ("connect-raw", "raw", False),
        ]
    if proto == "openconnect":
        return [
            ("connect-dtls", "dtls", True),
            ("connect-tls", "tls", False),
        ]
    return [("connect", None, True)]


def _run_mtproto(cA: Client, cB: Client, cC: Client, sc, result, panel, server_exec, mode: str) -> None:
    """MTProto Proxy suite for ONE connection mode.

    Deliberately NOT the shared tunnel suite. MTProto assigns no address, so
    tunnel_egress / dns_leak / dns_resolve / routing / client-to-client /
    cross-inbound / multi-inbound-by-IP have nothing to act on: they are not
    "skipped for now", they are inapplicable, and each is recorded NA with the
    reason rather than quietly omitted.

    What is actually proven here, per mode:
      connect: the real client half of the handshake is spoken from the
                       client VM and the proxy relays us to a live Telegram DC
                       (resPQ echoes our nonce). For tls the FakeTLS ServerHello
                       HMAC is also verified, which only a secret-holder can forge.
      wrong-secret: the negative control. Without it "connect passed" would be
                       unfalsifiable; with it, a proxy that accepted anything fails.
      multi-user: both accounts work independently on one inbound.
      usage: bytes driven by the prober land in the account's traffic.
    """
    from .clients import mtproto as mt_mod
    from .model import MTPROTO_PHASE_BY_MODE

    phase: Phase = result.phase(MTPROTO_PHASE_BY_MODE[mode])
    ib = sc.inbounds.get("mtproto")
    log = cA.log

    if ib is None:
        phase.add(SubTest("mtproto-inbound", Status.SKIP, "no mtproto inbound was built"))
        return

    # Dependency + reachability preconditions. A missing dep is a FAIL (we control
    # the image); an unreachable Telegram is NA (we do not control the network).
    # Push to BOTH clients: multi-user drives account B from cB, and a cB without the
    # prober fails with an error that looks like account B being broken.
    for c, tag in ((cA, "A"), (cB, "B")):
        ok, plog = mt_mod.ensure_probe(c)
        if not ok:
            phase.add(SubTest("mtproto-probe", Status.FAIL, f"client {tag}: {plog[:180]}"))
            log(f"-> mtproto-probe [fail] client {tag}: {plog[:120]}")
            return
    reach, rlog = mt_mod.dc_reachable(server_exec)
    if not reach:
        phase.add(SubTest("connect", Status.NA,
                          f"server cannot reach any Telegram DC: {rlog[:120]}"))
        log("-> connect [na] no Telegram DC reachable from the server")
        return

    # --- connect (the whole point) ---
    # The prober returns a VERDICT, not a bool: "na" means it could not decide
    # (e.g. the DC went unreachable mid-run), which must never read as PASS.
    _V = {"pass": Status.PASS, "fail": Status.FAIL, "na": Status.NA}
    st = phase.add(SubTest(f"connect-{mode}"))
    verdict, info, raw = mt_mod.probe(cA, ib, "A", mode, server_ip=sc.server_ip)
    st.status = _V.get(verdict, Status.ERROR)
    if verdict == "pass":
        extra = " +faketls-verified" if info.get("faketls_verified") else ""
        st.detail = (f"{info.get('codec', '?')}: relayed to a real DC"
                     f" (server_nonce {str(info.get('server_nonce', ''))[:16]}){extra}")
    else:
        st.detail = str(info.get("error") or raw)[:250]
        # A refused connection means telemt is not listening at all, which is a
        # server-side problem the client-side error cannot describe. Pull the core's
        # own state + log so the report says WHY instead of just "refused".
        if panel is not None:
            try:
                cs = panel.core("mtproto")
                clog = panel.core_logs("mtproto") or ""
                st.detail += (f" | core state={cs.get('state')} detail={cs.get('detail', '')}"
                              f" | log: {clog.strip()[-400:]}")
            except Exception as e:  # noqa: BLE001
                st.detail += f" | (core status unavailable: {e})"
    log(f"-> connect-{mode} [{st.status.value}] {st.detail}")

    # --- negative control: a wrong secret MUST be refused ---
    # Without this, "connect passed" is unfalsifiable: a proxy that accepted every
    # secret would look perfect. expect_fail inverts the prober's verdict, so PASS
    # here means "correctly refused".
    ns = phase.add(SubTest(f"wrong-secret-{mode}"))
    if st.status is not Status.PASS:
        # Same trap as multi-user below: a dead port refuses a wrong secret exactly as
        # convincingly as a working proxy does, so this only means something once we
        # know the proxy is actually serving.
        ns.status = Status.NA
        ns.detail = "undecidable: the proxy did not serve account A, so a refusal proves nothing"
    else:
        bad_verdict, bad_info, bad_raw = mt_mod.probe(
            cA, ib, "A", mode, server_ip=sc.server_ip,
            secret_override="f" * 32, expect_fail=True)
        ns.status = _V.get(bad_verdict, Status.ERROR)
        ns.detail = (f"refused as expected: {str(bad_info.get('error', ''))[:120]}"
                     if bad_verdict == "pass"
                     else "the proxy ACCEPTED a wrong secret: every connect result above is meaningless")
    log(f"-> wrong-secret-{mode} [{ns.status.value}] {ns.detail}")

    # --- multi-user: a SECOND account on the same inbound, same modes ---
    # The modes belong to the inbound (telemt's listener set is process-wide and its
    # per-user map is written from that same set), so both accounts hold all three.
    # What this proves is the other half: two accounts served by one telemt relay
    # independently, each authenticating with its own secret.
    ms = phase.add(SubTest(f"multi-user-{mode}"))
    b_verdict, b_info, _ = mt_mod.probe(cB, ib, "B", mode, server_ip=sc.server_ip)
    if st.status is not Status.PASS:
        # A dead port fails everyone, so B's result says nothing about B until the
        # proxy is known to be serving. Account A's connect above is that witness.
        ms.status = Status.NA
        ms.detail = (f"undecidable: account A could not connect either, so B failing "
                     f"on {mode} says nothing about the second account")
    else:
        ms.status = _V.get(b_verdict, Status.ERROR)
        ms.detail = ("account B relayed independently with its own secret"
                     if b_verdict == "pass" else str(b_info.get("error", ""))[:200])
    log(f"-> multi-user-{mode} [{ms.status.value}] {ms.detail}")

    # --- inapplicable by construction, not skipped ---
    for name, why in (
        ("dns-leak", "no tunnel: the client keeps its own resolver and its own IP"),
        ("routing", "routes per-INBOUND via its socks tag, and per-CLIENT via the socks "
                    "username (not a source IP, which a relay has none of); asserting the "
                    "per-client half needs its own rule set, so it is not covered here"),
        ("cross-inbound", "no tunnel addresses to route between"),
        ("user-limit", "per-account (user_max_unique_ips) and enforced inside telemt by "
                       "refusing the excess device; observing it needs more distinct client "
                       "IPs than the rig has VMs"),
    ):
        phase.add(SubTest(f"{name}", Status.NA, why))

    # --- usage: bytes driven through the proxy must be billed to the account ---
    # This is the one test of the accounting path that replaces nft for mtproto:
    # telemt's per-user counters -> the panel's Prometheus scrape -> client_traffics.
    us = phase.add(SubTest(f"usage-{mode}"))
    if panel is None:
        us.status = Status.SKIP
        us.detail = "no panel handle"
    else:
        try:
            email = ib.accounts["A"].email
            before, _ = traffic._counted(panel, email)
            pushed, dinfo, _ = mt_mod.drive_bytes(
                cA, ib, "A", mode, sc.server_ip, target_bytes=256 * 1024)
            # The traffic job ticks every 10s; give it two ticks plus slack so a
            # slow tick is not misread as "accounting is broken".
            time.sleep(25)
            after, row = traffic._counted(panel, email)
            if pushed <= 0:
                us.status = Status.ERROR
                us.detail = f"prober pushed no bytes: {str(dinfo.get('error', ''))[:160]}"
            elif after > before:
                us.status = Status.PASS
                us.detail = (f"pushed {pushed}B; counted {before} -> {after} "
                             f"(up={row.get('up')} down={row.get('down')})")
            else:
                us.status = Status.FAIL
                us.detail = f"pushed {pushed}B but usage did not rise ({before} -> {after})"
        except Exception as e:  # noqa: BLE001
            us.status = Status.ERROR
            us.detail = str(e)[:200]
    log(f"-> usage-{mode} [{us.status.value}] {us.detail}")

    # Traffic Multiplier. MTProto never reaches the shared traffic block (it is a
    # relay, not a tunnel), and its accounting is a Prometheus scrape rather than
    # nft counters, so if the multiplier were wired into the tunnel path only, this
    # is exactly the protocol that would silently bill 1:1 forever.
    tm = SubTest(f"traffic-multiplier-{mode}")
    if panel is None:
        tm.status, tm.detail = Status.SKIP, "no panel handle"
    else:
        try:
            email = ib.accounts["A"].email
            after_bytes, mult = 32 * 1024, 10.0
            # Re-saving restarts the relay, so set the policy BEFORE driving bytes.
            panel.set_traffic_multiplier(ib.inbound_id, True, after_bytes, mult)
            panel.reset_client_traffic(ib.inbound_id, email)
            time.sleep(6)
            before, _ = traffic._counted(panel, email)
            pushed, dinfo, _ = mt_mod.drive_bytes(
                cA, ib, "A", mode, sc.server_ip, target_bytes=256 * 1024)
            time.sleep(25)  # two 10s accounting ticks plus slack
            after, row = traffic._counted(panel, email)
            delta = after - before
            ratio = (delta / pushed) if pushed else 0
            tm.log = (f"pushed {pushed}B past a {after_bytes}B threshold at {mult}x; "
                      f"counted {before} -> {after} (delta {delta}, {ratio:.2f}x); "
                      f"up={row.get('up')} down={row.get('down')}")
            if pushed <= 0:
                tm.status = Status.ERROR
                tm.detail = f"prober pushed no bytes: {str(dinfo.get('error', ''))[:120]}"
            elif delta <= 0:
                tm.status, tm.detail = Status.FAIL, "no traffic counted at all"
            elif delta < pushed * 2.0:
                # Counted ~= pushed means the bytes were billed 1:1.
                tm.status = Status.FAIL
                tm.detail = (f"counted {delta}B for {pushed}B ({ratio:.2f}x): NOT weighted "
                             f"(expected ~{mult}x past {after_bytes}B)")
            else:
                tm.status = Status.PASS
                tm.detail = f"counted {delta}B for {pushed}B ({ratio:.2f}x, policy {mult}x)"
        except Exception as e:  # noqa: BLE001
            tm.status, tm.detail = Status.ERROR, str(e)[:200]
        finally:
            # Hand the account back un-weighted, or a later phase misreads its counter.
            try:
                panel.set_traffic_multiplier(ib.inbound_id, False, 0, 1)
                panel.reset_client_traffic(ib.inbound_id, email)
            except Exception as e:  # noqa: BLE001
                log(f"   (traffic-multiplier cleanup failed: {e})")
    phase.add(tm)
    log(f"-> {tm.name} [{tm.status.value}] {tm.detail}")

    mt_mod.disconnect(cA)
    mt_mod.disconnect(cB)


def _run_mtproto_toggle(cA: Client, sc, result, panel, server_exec) -> None:
    """Editing the inbound's modes must take effect on the RUNNING daemon.

    The per-mode phases cannot prove this: they read a mode set fixed at inbound
    creation. Here the modes are edited through the panel's inbound update endpoint,
    the same call the inbound form makes. They are inbound-level because telemt
    applies them that way: [general.modes] is the process-wide listener set, and
    [access.user_modes] is written per account from that same set.

    Getting this to be able to FAIL takes care. As built the inbound holds all three
    modes, so telemt STARTS with the listener wide open; flipping a mode off and back
    on then passes even if nothing reached the daemon, because the stale startup
    value already allows everything. The test would be vacuous.

    So the set is first narrowed and the core restarted, making telemt start with tls
    genuinely off. Only then does turning tls back on require the change to actually
    reach the daemon, which is the failure this phase exists to catch.

    Sequence:
      1. inbound := secure only
      2. restart core   -> telemt now STARTS with tls off (the setup step that makes
                           step 5 meaningful, not the test)
      3. probe A tls    -> must be REFUSED (baseline: tls really is off)
      4. inbound := secure+tls
      5. probe A tls    -> must WORK. Fails if the save never reached the listener:
                           it keeps refusing a mode the config on disk enables.
      6. restore inbound := all three
    """
    from .clients import mtproto as mt_mod
    from .model import PHASE_MTPROTO_TOGGLE

    phase: Phase = result.phase(PHASE_MTPROTO_TOGGLE)
    ib = sc.inbounds.get("mtproto")
    log = cA.log

    if ib is None or panel is None:
        phase.add(SubTest("mtproto-toggle", Status.SKIP, "no mtproto inbound was built"))
        return

    ok, plog = mt_mod.ensure_probe(cA)
    if not ok:
        phase.add(SubTest("mtproto-toggle", Status.FAIL, f"prober unavailable: {plog[:160]}"))
        return
    reach, rlog = mt_mod.dc_reachable(server_exec)
    if not reach:
        phase.add(SubTest("toggle-on-tls", Status.NA,
                          f"server cannot reach any Telegram DC: {rlog[:120]}"))
        return

    _V = {"pass": Status.PASS, "fail": Status.FAIL, "na": Status.NA}
    try:
        # --- 1+2: narrow the inbound to {secure} and RESTART -------------
        # Setup, not assertion: it makes telemt start with tls genuinely off, which
        # is the only state in which step 5 can detect a stale [general.modes].
        panel.set_mtproto_modes(ib.inbound_id, ("secure",))
        panel.restart_core("mtproto")
        time.sleep(MTPROTO_RELOAD_WAIT)

        # --- 3: with tls off on the inbound, it must be refused ---------
        # Baseline. Without it, "tls works after toggle-on" could just mean tls was
        # never actually off, and the phase would prove nothing.
        off = phase.add(SubTest("toggle-off-tls"))
        v, info, _ = mt_mod.probe(cA, ib, "A", "tls", server_ip=sc.server_ip,
                                  expect_fail=True)
        off.status = _V.get(v, Status.ERROR)
        off.detail = ("tls refused while the inbound does not accept it"
                      if v == "pass"
                      else "tls STILL works with the toggle off on the inbound: "
                           "the edit did not reach the running daemon")
        log(f"-> toggle-off-tls [{off.status.value}] {off.detail}")

        # --- 4+5: turn tls back ON. It must start working ---------------
        # The listener set goes {secure} -> {secure,tls}. If the save does not reach
        # the daemon, it keeps refusing FakeTLS while config.toml says it is enabled:
        # the "backend ignores the toggle" bug, caught right here.
        panel.set_mtproto_modes(ib.inbound_id, ("secure", "tls"))
        time.sleep(MTPROTO_RELOAD_WAIT)
        on = phase.add(SubTest("toggle-on-tls"))
        if off.status is not Status.PASS:
            on.status = Status.NA
            on.detail = ("undecidable: tls was not actually off beforehand, so it "
                         "working now proves nothing about the toggle")
        else:
            v, info, _ = mt_mod.probe(cA, ib, "A", "tls", server_ip=sc.server_ip)
            on.status = _V.get(v, Status.ERROR)
            if v == "pass":
                on.detail = ("tls works right after being toggled on "
                             "(both [general.modes] and [access.user_modes] followed)")
            else:
                on.detail = (f"tls did NOT work after being toggled on: "
                             f"{str(info.get('error', ''))[:140]}, the toggle is not "
                             f"reaching the running daemon")
                try:
                    cs = panel.core("mtproto")
                    on.detail += f" | core state={cs.get('state')}"
                    clog = panel.core_logs("mtproto") or ""
                    on.detail += f" | log: {clog.strip()[-250:]}"
                except Exception:  # noqa: BLE001
                    pass
        log(f"-> toggle-on-tls [{on.status.value}] {on.detail}")

        # --- the core has to come BACK from the edit --------------------
        # The modes live in a section telemt reads at startup, so an inbound save
        # restarts it. That is the moment a bad config shows up: telemt refuses to
        # start and every account on the inbound goes dark while the panel reports
        # the save as successful.
        hot = phase.add(SubTest("toggle-core-healthy"))
        try:
            cs = panel.core("mtproto")
            hot.status = Status.PASS if cs.get("state") == "running" else Status.FAIL
            hot.detail = (f"core is running again after the mode edit (state={cs.get('state')})"
                          if hot.status is Status.PASS
                          else f"core state={cs.get('state')} after the mode edit")
        except Exception as e:  # noqa: BLE001
            hot.status = Status.ERROR
            hot.detail = f"core status unavailable: {e}"
        log(f"-> toggle-core-healthy [{hot.status.value}] {hot.detail}")
    finally:
        # Leave the inbound exactly as the other phases expect to find it.
        try:
            panel.set_mtproto_modes(ib.inbound_id, ("classic", "secure", "tls"))
            time.sleep(MTPROTO_RELOAD_WAIT)
        except Exception as e:  # noqa: BLE001
            phase.add(SubTest("toggle-restore", Status.ERROR,
                              f"could not restore the inbound modes: {e}"))


def _run_mtproto_termination(cA: Client, sc, result, panel, server_exec) -> None:
    """Quota -> auto-disable -> the account can no longer relay.

    The per-mode `usage` subtest proves bytes are COUNTED. It says nothing about them
    being ENFORCED, and those are different code paths: mtproto has neither RADIUS nor
    nft, so enforcement is the panel re-rendering [access.user_enabled] from
    client_traffics and telemt's config watcher cancelling the account's live sessions.
    Nothing covered that, which is the same shape as the ikev2 psk/eap-tls leak (evicted
    every tick, but re-admitted in the gaps because the daemon was never told).

    Two subtests, deliberately split: "the DB flipped enable=false" and "the proxy
    actually stops serving it" are different claims, and the whole class of bug lives in
    the gap between them. A single merged verdict would report the leak as a quota
    failure and send the next reader to the wrong file.

    Scale note: the quota is KiB, not MB. The prober's ceiling is ~1.6 KiB/s per
    connection (each req_pq is a full round-trip to a DC, which does not pipeline
    unauthenticated requests), so the MB-scale limit traffic.termination uses for tunnel
    protocols could never be driven over here. That helper is tunnel-shaped anyway: it
    curls through an interface this protocol does not have.
    """
    from .clients import mtproto as mt_mod
    from .model import PHASE_MTPROTO_TERMINATION

    phase: Phase = result.phase(PHASE_MTPROTO_TERMINATION)
    ib = sc.inbounds.get("mtproto")
    log = cA.log

    if ib is None or panel is None:
        phase.add(SubTest("mtproto-termination", Status.SKIP, "no mtproto inbound was built"))
        return
    ok, plog = mt_mod.ensure_probe(cA)
    if not ok:
        phase.add(SubTest("mtproto-termination", Status.FAIL, f"prober unavailable: {plog[:160]}"))
        return
    reach, rlog = mt_mod.dc_reachable(server_exec)
    if not reach:
        phase.add(SubTest("account-termination", Status.NA,
                          f"server cannot reach any Telegram DC: {rlog[:120]}"))
        return

    _V = {"pass": Status.PASS, "fail": Status.FAIL, "na": Status.NA}
    email = ib.accounts["A"].email
    mode = "secure"          # account A holds every mode; secure needs no FakeTLS domain
    limit = 64 * 1024        # KiB-scale on purpose (see the docstring)
    push = 256 * 1024        # 4x the limit, ~7s at the prober's measured rate

    try:
        # Zero the counter BEFORE arming the quota, not after. The mode phases already
        # billed this account ~768 KiB (256 KiB per usage subtest), which is well past a
        # 64 KiB limit: arming first would let the very next traffic tick disable the
        # account before the baseline probe, and the phase would measure its own setup.
        panel.reset_client_traffic(ib.inbound_id, email)
        time.sleep(MTPROTO_RELOAD_WAIT)
        panel.set_client_total(ib.inbound_id, email, limit)
        time.sleep(MTPROTO_RELOAD_WAIT)

        # Baseline. A limited-but-under-quota account must relay, or "it stopped working
        # after the quota" proves nothing: it might never have worked in this phase.
        base = phase.add(SubTest("termination-baseline"))
        v, info, _ = mt_mod.probe(cA, ib, "A", mode, server_ip=sc.server_ip)
        base.status = _V.get(v, Status.ERROR)
        base.detail = ("account relays while under its quota"
                       if v == "pass" else str(info.get("error", ""))[:200])
        log(f"-> termination-baseline [{base.status.value}] {base.detail}")

        st = phase.add(SubTest("account-termination"))
        en = phase.add(SubTest("termination-enforced"))
        if base.status is not Status.PASS:
            st.status = en.status = Status.NA
            st.detail = en.detail = ("undecidable: the account did not relay before the "
                                     "quota, so it not relaying after proves nothing")
            log(f"-> account-termination [na] {st.detail}")
            return

        pushed, dinfo, _ = mt_mod.drive_bytes(cA, ib, "A", mode, sc.server_ip,
                                              target_bytes=push)
        if pushed <= 0:
            st.status = Status.ERROR
            st.detail = f"prober pushed no bytes: {str(dinfo.get('error', ''))[:160]}"
            en.status = Status.NA
            en.detail = "undecidable: no traffic was driven, so no quota could be crossed"
            log(f"-> account-termination [error] {st.detail}")
            return

        # Poll for the auto-disable. The scrape + AddTraffic run on the 10s traffic job,
        # and the disable lands a tick after the bytes do, so allow several ticks.
        disabled, row = False, {}
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            row = panel.get_client_traffics(email) or {}
            if not bool(row.get("enable", True)):
                disabled = True
                break
            time.sleep(4)
        counted = int(row.get("up", 0) or 0) + int(row.get("down", 0) or 0)

        if not disabled:
            # Distinguish "enforcement is broken" from "we never actually crossed the
            # line": only the former is this suite's bug to report.
            if counted < limit:
                st.status = Status.NA
                st.detail = (f"could not drive past the {limit}B limit "
                             f"(pushed {pushed}B, counted {counted}B)")
            else:
                st.status = Status.FAIL
                st.detail = (f"account NOT disabled despite counted {counted}B "
                             f"over a {limit}B limit")
            en.status = Status.NA
            en.detail = "undecidable: the account was never disabled"
            log(f"-> account-termination [{st.status.value}] {st.detail}")
            return
        st.status = Status.PASS
        st.detail = f"auto-disabled after counted {counted}B over a {limit}B limit"
        log(f"-> account-termination [pass] {st.detail}")

        # THE point of the phase. enable=false in the DB is not enforcement: the ikev2
        # psk/eap-tls bug looked exactly like this and still relayed. Only a refused
        # handshake proves the verdict reached the running daemon.
        v, info, _ = mt_mod.probe(cA, ib, "A", mode, server_ip=sc.server_ip,
                                  expect_fail=True)
        en.status = _V.get(v, Status.ERROR)
        en.detail = ("the disabled account is refused by the proxy"
                     if v == "pass"
                     else "the account is disabled in the DB but STILL relays: "
                          "[access.user_enabled] is not reaching the running daemon")
        if en.status is not Status.PASS:
            try:
                cs = panel.core("mtproto")
                en.detail += f" | core state={cs.get('state')}"
            except Exception:  # noqa: BLE001
                pass
        log(f"-> termination-enforced [{en.status.value}] {en.detail}")

        # Re-enabling must bring it back, or a quota trip would be a one-way door for
        # the operator. This is also the mirror of the enforcement assertion: it proves
        # the refusal above came from the account's state and not from a wedged daemon.
        panel.set_client_total(ib.inbound_id, email, 0)
        panel.reset_client_traffic(ib.inbound_id, email)
        time.sleep(MTPROTO_RELOAD_WAIT)
        re = phase.add(SubTest("termination-reenable"))
        v, info, _ = mt_mod.probe(cA, ib, "A", mode, server_ip=sc.server_ip)
        re.status = _V.get(v, Status.ERROR)
        re.detail = ("the re-enabled account relays again"
                     if v == "pass"
                     else f"still refused after re-enable: {str(info.get('error', ''))[:140]}")
        log(f"-> termination-reenable [{re.status.value}] {re.detail}")
    finally:
        # Leave the account unlimited + enabled: later phases (and a re-run) assume it.
        try:
            panel.set_client_total(ib.inbound_id, email, 0)
            panel.reset_client_traffic(ib.inbound_id, email)
            time.sleep(MTPROTO_RELOAD_WAIT)
        except Exception as e:  # noqa: BLE001
            phase.add(SubTest("termination-restore", Status.ERROR,
                              f"could not restore account A: {e}"))
        mt_mod.disconnect(cA)


def _run_mtproto_adtag(cA: Client, sc, result, panel, server_exec) -> None:
    """An Ad Tag turns middle-proxy mode on for the whole inbound, and Xray routing off.

    Why the client cannot see any of this: the tag rides the proxy->Telegram leg (a
    RPC_PROXY_REQ field, flagged RPC_FLAG_HAS_AD_TAG). The client->proxy handshake is
    byte-identical with the tag on or off, so the prober can never tell them apart and a
    client-side assertion would be pure theatre. Every check here is server-side.

    What is NOT covered, deliberately: that Telegram actually credits the tag and renders
    the sponsored channel. That needs a real account, and it is Telegram's behavior, not
    the panel's. What IS covered is the whole of the panel's contract:

      adtag-off-routing : baseline. The inbound HAS its Xray socks inbound while untagged.
      adtag-xray-off    : tagging any account drops it -> the operator's routing rules stop
                          applying to EVERY account on the inbound. This is the XOR, the
                          one thing a user can be surprised by, and it was untested.
      adtag-config      : telemt is actually told: use_middle_proxy + a direct upstream +
                          [access.user_ad_tags] carrying the tag.
      adtag-middle-proxy: telemt actually ENTERED that path rather than silently taking
                          its me2dc_fallback back to direct mode (see below).
      adtag-relay       : the proxy STILL relays once on the middle-proxy path, so the
                          routing traded away bought something.
      adtag-restore     : clearing the tag restores the socks inbound (the XOR is a toggle,
                          not a one-way door) and leaves the rig as other phases expect.

    Restart, not hot-reload: use_middle_proxy needs a socket re-bind, which telemt's
    hot-reload path skips with a warning. A client-only edit would leave the running
    daemon on the old path and every assertion below would read the wrong process.

    The trap that makes adtag-middle-proxy necessary: middle-proxy mode must first fetch
    Telegram's proxy-secret (a different secret from the user's), and telemt's
    me2dc_fallback defaults to TRUE, which the panel never overrides. If that fetch
    fails, telemt logs "falling back to direct mode" and relays perfectly well with no
    tag on the wire. A relay-only assertion would go green on exactly the state the
    operator is paying routing for and not getting.

    And there are TWO ways to end up on that silent direct path, which is why the check
    is not just "did it fall back". telemt logs the middle-proxy banner BEFORE its ME
    pool exists, then serves over a direct fallback while the pool builds. If the pool
    never comes up (every ME server refusing the handshake), the banner is still there,
    nothing says "falling back", and no tag is ever sent. That is the failure a NATed
    host hits, and it is the one that reached a real user.
    """
    from .clients import mtproto as mt_mod
    from .model import PHASE_MTPROTO_ADTAG

    phase: Phase = result.phase(PHASE_MTPROTO_ADTAG)
    ib = sc.inbounds.get("mtproto")
    log = cA.log

    if ib is None or panel is None:
        phase.add(SubTest("mtproto-adtag", Status.SKIP, "no mtproto inbound was built"))
        return
    ok, plog = mt_mod.ensure_probe(cA)
    if not ok:
        phase.add(SubTest("mtproto-adtag", Status.FAIL, f"prober unavailable: {plog[:160]}"))
        return

    # Exactly 32 hex chars. telemt rejects any other length and then runs WITHOUT the
    # tag, which would quietly turn every assertion below into a test of nothing.
    tag = "0123456789abcdef0123456789abcdef"
    email = ib.accounts["A"].email
    conf = f"/etc/vpn-ui-mtproto/server-{ib.inbound_id}/config.toml"

    # The paired socks inbound lands on the panel-wide "Xray port for inbound N is
    # 12300+N" convention (GetSocksPort), which is stable and inbound-unique.
    socks_port = 12300 + ib.inbound_id

    def socks_inbound_present() -> tuple[bool, str]:
        """Is the inbound's paired Xray socks inbound in the MERGED runtime config?
        That inbound is the whole of mtproto's Xray routing: GetSocksConfig returns nil
        when any account carries a tag, so its presence IS 'routing applies here'."""
        try:
            cfgj = panel.get_config_json() or {}
        except Exception as e:  # noqa: BLE001
            return False, f"could not read the merged Xray config: {e}"
        found = [i for i in (cfgj.get("inbounds") or [])
                 if i.get("protocol") == "socks" and i.get("port") == socks_port]
        return bool(found), f"socks inbounds on port {socks_port}: {len(found)}"

    def telemt_egress_is_socks() -> tuple[bool, str]:
        """Is the RUNNING telemt egressing through Xray, rather than direct?

        The config on disk is NOT evidence. telemt cannot hot-reload use_middle_proxy or
        [[upstreams]], so a file that says socks5 says nothing about the live process:
        that gap is precisely the production bug (tag cleared, config correct, telemt
        still egressing direct, Xray routing silently not applying).

        The middle-proxy path holds persistent writer connections to Telegram's ME
        servers on :8888; the socks path never opens one. So a live :8888 socket owned
        by telemt means it is still on the direct egress.
        """
        if server_exec is None:
            return True, "no server_exec (cannot inspect telemt egress)"
        try:
            _, out, _ = server_exec(
                "ss -tnp state established 2>/dev/null | grep telemt | grep -c ':8888' || true",
                timeout=25)
        except Exception as e:  # noqa: BLE001
            return True, f"egress probe failed: {e}"
        raw = (out or "").strip().splitlines()
        try:
            live = int(raw[-1].strip()) if raw else 0
        except ValueError:
            live = 0
        return live == 0, (f"telemt still holds {live} middle-proxy (:8888) connections"
                           if live else "telemt holds no middle-proxy connections")

    try:
        # --- baseline: untagged, the socks inbound must be there -------------
        # Without this, "the socks inbound is gone after tagging" could just mean it was
        # never generated, and the XOR assertion below would be vacuous.
        off = phase.add(SubTest("adtag-off-routing"))
        present, pdetail = socks_inbound_present()
        off.status = Status.PASS if present else Status.FAIL
        off.detail = (f"untagged inbound routes through Xray ({pdetail})" if present
                      else f"no Xray socks inbound while UNTAGGED ({pdetail}): "
                           f"mtproto routing is already off, so the adtag XOR "
                           f"cannot be demonstrated")
        log(f"-> adtag-off-routing [{off.status.value}] {off.detail}")

        # --- tag account A. NO restart_core here, on purpose -----------------
        # use_middle_proxy + [[upstreams]] are not hot-reloadable, so the PANEL has to
        # notice the egress moved and restart telemt itself. Restarting from the test
        # would do the panel's job for it and hide the bug that reached production:
        # telemt kept the old egress and either refused every client (tag on, dialing a
        # socks port the panel had just deleted) or silently bypassed Xray routing
        # entirely (tag off, still egressing direct).
        panel.set_mtproto_adtag(ib.inbound_id, email, tag)
        time.sleep(MTPROTO_RELOAD_WAIT * 2)

        # --- the XOR ---------------------------------------------------------
        xo = phase.add(SubTest("adtag-xray-off"))
        if off.status is not Status.PASS:
            xo.status = Status.NA
            xo.detail = ("undecidable: the socks inbound was already absent before "
                         "tagging, so its absence now proves nothing")
        else:
            still, sdetail = socks_inbound_present()
            xo.status = Status.PASS if not still else Status.FAIL
            xo.detail = ("tagging an account dropped the inbound's Xray socks inbound: "
                         "routing correctly stops applying to every account on it"
                         if not still else
                         f"the Xray socks inbound SURVIVED an ad tag ({sdetail}): telemt "
                         f"is on the middle-proxy path but Xray still re-originates its "
                         f"egress, so the ME handshake cannot key and the tag is broken")
        log(f"-> adtag-xray-off [{xo.status.value}] {xo.detail}")

        # --- telemt is actually told ----------------------------------------
        cf = phase.add(SubTest("adtag-config"))
        try:
            _, toml, _ = server_exec(f"cat {conf} 2>/dev/null || true", timeout=30)
            toml = toml or ""
            missing = []
            if "use_middle_proxy = true" not in toml:
                missing.append("use_middle_proxy = true")
            if "[access.user_ad_tags]" not in toml:
                missing.append("[access.user_ad_tags]")
            if tag not in toml:
                missing.append("the tag itself")
            if 'type = "direct"' not in toml:
                missing.append('an [[upstreams]] type = "direct"')
            if not toml.strip():
                cf.status = Status.ERROR
                cf.detail = f"{conf} is empty or unreadable"
            elif missing:
                cf.status = Status.FAIL
                cf.detail = ("config.toml is missing " + ", ".join(missing) +
                             " with an ad tag set")
            else:
                cf.status = Status.PASS
                cf.detail = ("config.toml carries use_middle_proxy, a direct upstream "
                             "and the per-account tag")
        except Exception as e:  # noqa: BLE001
            cf.status = Status.ERROR
            cf.detail = f"could not read {conf}: {e}"
        log(f"-> adtag-config [{cf.status.value}] {cf.detail}")

        # --- did telemt actually ENTER middle-proxy mode? --------------------
        # The vacuity trap of this whole phase. Middle-proxy needs Telegram's
        # proxy-secret (a different secret from the user's), and telemt's me2dc_fallback
        # defaults to TRUE, which the panel never overrides: if that fetch fails it logs
        # "falling back to direct mode" and keeps relaying happily WITHOUT the tag. So a
        # relay check alone would go green while the tag does nothing. Fetch failure is a
        # network fault (NA); never entering the mode at all is a real bug (FAIL).
        mp = phase.add(SubTest("adtag-middle-proxy"))
        clog = ""
        try:
            clog = panel.core_logs("mtproto") or ""
        except Exception as e:  # noqa: BLE001
            mp.status = Status.ERROR
            mp.detail = f"core logs unavailable: {e}"
        if mp.status is not Status.ERROR:
            fell_back = "falling back to direct mode" in clog
            entered = "=== Middle Proxy Mode ===" in clog
            # "Entered middle-proxy mode" is NOT the same as "the ME pool came up", and
            # the difference is the whole test. telemt logs the banner, then builds its
            # ME pool in the background and serves over a DIRECT fallback until it is
            # ready. If every ME server rejects the handshake the pool stays empty, the
            # fallback becomes permanent, and NO tag is ever sent, while the banner sits
            # in the log looking like success. Real cause seen in the field: behind a
            # port-rewriting NAT the ME session key (derived from the proxy's own
            # ip:PORT on both sides independently) never matches, so Telegram drops every
            # connection with an early eof. That is an environment limit, not a panel
            # bug, hence NA rather than FAIL: the panel cannot give a NATed host a
            # stable public port.
            pool_dead = "All ME servers for DC failed at init" in clog
            if fell_back:
                mp.status = Status.NA
                mp.detail = ("telemt could not fetch Telegram's proxy-secret and fell "
                             "back to direct mode (me2dc_fallback), so the tag is not "
                             "on the wire: an egress limitation of this network, not a "
                             "panel bug")
            elif pool_dead:
                mp.status = Status.NA
                mp.detail = ("telemt entered middle-proxy mode but EVERY ME server "
                             "refused its handshake (pool alive=0), so it serves over "
                             "the direct fallback and sends no tag. Typically this host "
                             "has no stable public ip:port (NAT rewrites the source "
                             "port), which the ME key derivation cannot survive")
            elif entered:
                mp.status = Status.PASS
                mp.detail = "telemt entered middle-proxy mode and did not fall back"
            else:
                mp.status = Status.FAIL
                mp.detail = ("telemt never logged middle-proxy startup after the tag + "
                             "restart: use_middle_proxy did not reach the running daemon")
        log(f"-> adtag-middle-proxy [{mp.status.value}] {mp.detail}")

        # --- and it still relays --------------------------------------------
        # Only meaningful once we know the middle-proxy path is the one being used:
        # relaying via the direct fallback says nothing about the tagged path.
        rel = phase.add(SubTest("adtag-relay"))
        reach, rlog = mt_mod.dc_reachable(server_exec)
        if mp.status is not Status.PASS:
            rel.status = Status.NA
            rel.detail = ("undecidable: telemt is not on the middle-proxy path "
                          f"({mp.detail[:90]})")
        elif not reach:
            rel.status = Status.NA
            rel.detail = f"server cannot reach any Telegram DC: {rlog[:120]}"
        else:
            v, info, _ = mt_mod.probe(cA, ib, "A", "secure", server_ip=sc.server_ip)
            rel.status = {"pass": Status.PASS, "fail": Status.FAIL,
                          "na": Status.NA}.get(v, Status.ERROR)
            rel.detail = ("the tagged account still relays, over the middle-proxy path"
                          if v == "pass" else
                          f"the tagged inbound stopped relaying: "
                          f"{str(info.get('error', ''))[:140]}")
            if rel.status is not Status.PASS:
                try:
                    rel.detail += f" | log: {(panel.core_logs('mtproto') or '').strip()[-300:]}"
                except Exception:  # noqa: BLE001
                    pass
        log(f"-> adtag-relay [{rel.status.value}] {rel.detail}")
    finally:
        # Clear the tag and prove the XOR reverses. This is both the restore (every later
        # phase assumes this inbound routes through Xray) and a real assertion.
        rs = phase.add(SubTest("adtag-restore"))
        try:
            # Again no restart_core: clearing the tag must put telemt BACK on the socks
            # upstream by itself. This is the dangerous direction, so it is asserted,
            # not assumed: a telemt left on the direct egress keeps relaying happily
            # while every Xray routing rule for the inbound quietly stops applying.
            panel.set_mtproto_adtag(ib.inbound_id, email, "")
            time.sleep(MTPROTO_RELOAD_WAIT * 2)
            back, bdetail = socks_inbound_present()
            egress_ok, egress_detail = telemt_egress_is_socks()
            rs.status = Status.PASS if (back and egress_ok) else Status.FAIL
            rs.detail = ("clearing the tag restored the Xray socks inbound and telemt "
                         "went back to egressing through it"
                         if back and egress_ok else
                         f"tag cleared but routing is NOT restored: "
                         f"socks_inbound_back={back} ({bdetail}); telemt_egress={egress_detail}")
        except Exception as e:  # noqa: BLE001
            rs.status = Status.ERROR
            rs.detail = f"could not clear the ad tag: {e}"
        log(f"-> adtag-restore [{rs.status.value}] {rs.detail}")
        mt_mod.disconnect(cA)


def _run_ssh_udp(cA: Client, sc, cfg: dict, result, panel, server_exec) -> None:
    """Dedicated UDP test for the SSH relay: prove UDP survives the badvpn-udpgw path
    end-to-end AND is billed to the account.

    The standard suite's dns-resolve / dns-leak checks can pass even if UDP is broken,
    because SSH tunnels TCP natively and DNS may fall back to TCP. This phase forces UDP: a
    `dig +notcp` to a public resolver traverses tun2socks -> udpgw -> the SSH server's
    in-process udpgw bridge -> Xray SOCKS UDP. A reply proves the whole UDP path; then a
    burst of UDP DNS queries must move the account's counted traffic (routed + accounted
    exactly like the TCP path, keyed on the socks username = email).

    Runs AFTER the main ssh phase, whose account-termination sub-test disables account A;
    so it first resets account A's traffic (re-enables + zeroes usage) before connecting,
    and the tiny UDP burst stays well under the account limit."""
    phase: Phase = result.phase(PHASE_SSH_UDP)
    ib = sc.inbounds.get("ssh")
    log = cA.log
    iface = ssh_mod.IFACE

    if ib is None:
        phase.add(SubTest("ssh-udp", Status.SKIP, "no ssh inbound was built"))
        return

    email = ib.accounts["A"].email
    cA.disconnect_all()
    time.sleep(2)
    # The main ssh phase's account-termination sub-test leaves account A disabled with a
    # usage limit; re-enable + zero it so the tunnel can come up here (the UDP burst is far
    # under the limit, so it will not re-trip enforcement).
    if panel is not None:
        try:
            panel.reset_client_traffic(ib.inbound_id, email)
            time.sleep(6)  # re-enable + on-ssh-changed daemon reconcile
        except Exception as e:  # noqa: BLE001
            log(f"-> (reset account A before ssh-udp failed: {e})")

    ok, ip, clog = _connect(cA, sc, "ssh", "A", ib=ib)
    if not ok:
        phase.add(SubTest("udp-connect", Status.SKIP,
                          "account A failed to bring up the ssh tunnel", clog))
        log("-> udp-connect [skip] tunnel did not come up")
        return

    resolver = "8.8.8.8"

    # --- functional: a UDP-only DNS lookup must resolve THROUGH the tunnel ---
    # +notcp forbids the TCP fallback, so a valid answer can only have come over UDP via
    # udpgw. The route to the resolver must egress dev tun0 (else it leaked off-tunnel).
    fn = phase.add(SubTest("udp-dns"))
    try:
        _, rg = cA.sh(f"ip route get {resolver} 2>/dev/null | head -1")
        via_tunnel = f"dev {iface}" in rg
        _, dig = cA.sh(
            f"dig +notcp +time=3 +tries=2 +short A example.com @{resolver} 2>&1")
        ips = [ln.strip() for ln in dig.splitlines()
               if ln.strip() and ln.strip()[0].isdigit()]
        fn.log = (f"route get {resolver}: {rg.strip()}\n"
                  f"dig +notcp @{resolver} example.com:\n{dig.strip()}")
        if ips and via_tunnel:
            fn.status = Status.PASS
            fn.detail = (f"UDP DNS via udpgw resolved example.com -> {', '.join(ips[:3])} "
                         f"(dev {iface}, +notcp)")
        elif ips and not via_tunnel:
            fn.status = Status.FAIL
            fn.detail = f"UDP DNS resolved but NOT via the tunnel (route: {rg.strip()[:80]})"
        else:
            fn.status = Status.FAIL
            fn.detail = f"UDP-only DNS (+notcp @{resolver}) did not resolve through the tunnel"
    except Exception as e:  # noqa: BLE001
        fn.status, fn.detail = Status.ERROR, str(e)[:150]
    log(f"-> udp-dns [{fn.status.value}] {fn.detail}")

    # --- accounting: a burst of UDP DNS must move the account's counted traffic ---
    # Baseline is read AFTER the functional dig, and only UDP is driven between the two
    # reads, so a rise can only be UDP bytes: if UDP were unaccounted the counter would
    # not move (no TCP is driven here) and this FAILs.
    us = phase.add(SubTest("udp-usage"))
    if panel is None:
        us.status, us.detail = Status.SKIP, "no panel handle"
    else:
        try:
            before, _ = traffic._counted(panel, email)
            # Drive many DISTINCT UDP queries (distinct names dodge caching, so each is a
            # real round-trip). Parallelised so the burst is quick; NXDOMAIN answers still
            # carry bytes, so the counter moves even without wildcard records.
            _, drove = cA.sh(
                "seq 1 400 | xargs -P 20 -I{} dig +notcp +time=2 +tries=1 +short "
                f"A udp{{}}.example.com @{resolver} >/dev/null 2>&1; echo DONE",
                timeout=120)
            # The traffic job folds every 10s; give it >=2 ticks plus slack.
            time.sleep(25)
            after, row = traffic._counted(panel, email)
            us.log = (f"drove 400 UDP DNS queries (parallel); counted {before} -> {after} "
                      f"(up={row.get('up')} down={row.get('down')})\ndrive={drove.strip()[-120:]}")
            if after > before:
                us.status = Status.PASS
                us.detail = (f"UDP traffic billed to the account: {before} -> {after} B "
                             f"(delta {after - before})")
            else:
                us.status = Status.FAIL
                us.detail = (f"UDP driven but the account usage did not rise "
                             f"({before} -> {after}) - UDP not accounted")
        except Exception as e:  # noqa: BLE001
            us.status, us.detail = Status.ERROR, str(e)[:150]
    log(f"-> udp-usage [{us.status.value}] {us.detail}")

    ssh_mod.disconnect(cA)
    cA.disconnect_all()


def _udp_dns_probe(client: Client, name: str, iface: str,
                   resolver: str = "8.8.8.8") -> SubTest:
    """A UDP-ONLY DNS lookup that must resolve THROUGH the tunnel.

    `+notcp` forbids dig's TCP fallback, so a valid answer can only have crossed the
    proxy as a datagram; the route check makes sure it went out `iface` rather than
    leaking to the physical default. This is the assertion the shared dns-resolve
    check cannot make: that one is satisfied by ANY working resolution, TCP included."""
    st = SubTest(name)
    try:
        _, rg = client.sh(f"ip route get {resolver} 2>/dev/null | head -1")
        via_tunnel = f"dev {iface}" in rg
        _, dig = client.sh(
            f"dig +notcp +time=3 +tries=2 +short A example.com @{resolver} 2>&1")
        ips = [ln.strip() for ln in dig.splitlines()
               if ln.strip() and ln.strip()[0].isdigit()]
        st.log = (f"route get {resolver}: {rg.strip()}\n"
                  f"dig +notcp @{resolver} example.com:\n{dig.strip()}")
        if ips and via_tunnel:
            st.status = Status.PASS
            st.detail = (f"UDP-only DNS resolved example.com -> {', '.join(ips[:3])} "
                         f"(dev {iface}, +notcp)")
        elif ips and not via_tunnel:
            st.status = Status.FAIL
            st.detail = f"UDP DNS resolved but NOT via the tunnel (route: {rg.strip()[:80]})"
        else:
            st.status = Status.FAIL
            st.detail = f"UDP-only DNS (+notcp @{resolver}) did not resolve through the tunnel"
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    return st


def _udp_usage_probe(client: Client, panel, ib, name: str = "udp-usage",
                     resolver: str = "8.8.8.8") -> SubTest:
    """A burst of UDP DNS must move the account's counted traffic.

    The baseline is read AFTER any functional probe and only UDP is driven between the
    two reads, so a rise can only be UDP bytes. For an Xray-native protocol this is a
    direct test of the one line the whole integration hangs on: the inbound must put
    the matched account on the session before dispatching, or the datagrams are
    forwarded perfectly and billed to nobody."""
    st = SubTest(name)
    if panel is None:
        st.status, st.detail = Status.SKIP, "no panel handle"
        return st
    try:
        email = ib.accounts["A"].email
        before, _ = traffic._counted(panel, email)
        # Distinct names dodge caching, so each query is a real round-trip; NXDOMAIN
        # answers still carry bytes. Parallelised so the burst is quick.
        _, drove = client.sh(
            "seq 1 400 | xargs -P 20 -I{} dig +notcp +time=2 +tries=1 +short "
            f"A udp{{}}.example.com @{resolver} >/dev/null 2>&1; echo DONE",
            timeout=120)
        time.sleep(25)          # the traffic job folds every 10s; >=2 ticks plus slack
        after, row = traffic._counted(panel, email)
        st.log = (f"drove 400 UDP DNS queries (parallel); counted {before} -> {after} "
                  f"(up={row.get('up')} down={row.get('down')})\ndrive={drove.strip()[-120:]}")
        if after > before:
            st.status = Status.PASS
            st.detail = (f"UDP traffic billed to the account: {before} -> {after} B "
                         f"(delta {after - before})")
        else:
            st.status = Status.FAIL
            st.detail = (f"UDP driven but the account usage did not rise "
                         f"({before} -> {after}) - UDP not accounted")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    return st


def _xray_udp_checks(proto: str, cA: Client, sc, ib, panel, log, phase) -> None:
    """UDP for the Xray-native protocols, which is where each of them is most likely to
    be quietly broken.

      * tuic carries UDP two entirely separate ways: `udpRelayMode: native` (one QUIC
        datagram per packet) and `quic` (UDP over a QUIC stream, reassembled by the
        server's defragmenter). Green on one says nothing about the other, so BOTH are
        dialed against the same inbound.
      * anytls has NO UDP transport: the client wraps UDP in the TLS stream (UoT) and
        the server unwraps it. One subtest, and it is a real test of that interception
        because clients/anytls.py deliberately does not route DNS around it.
      * naive is HTTP CONNECT and proxies no UDP at all: recorded NA, with the reason,
        rather than left absent.

    Runs while account A is disposable but still ENABLED (before the traffic block,
    whose termination sub-test disables it)."""
    if proto == "naive":
        # Said out loud because it would otherwise be an invisible caveat: naive's
        # dns-resolve / dns-leak greens are NOT UDP proofs. The client's own xray
        # answers UDP:53 locally from a resolver that queries over TCP through the
        # proxy (clients/naive.py), which is what a real naive deployment must do.
        for nm, why in (
            ("udp-dns",
             "naive is HTTP CONNECT over h2/h3 and proxies no UDP payload at all (its "
             "`network` field picks the CARRIER, h2 vs h3, not what it can forward). DNS "
             "is answered by the client's own xray over a TCP upstream carried through "
             "the proxy, so it never crosses naive as UDP: the dns-resolve / dns-leak "
             "passes above are TCP-DNS proofs"),
            ("udp-usage", "no UDP path to bill: see udp-dns"),
        ):
            phase.add(SubTest(nm, Status.NA, why))
            log(f"-> {nm} [na] {why}")
        return

    modes = tuic_mod.UDP_MODES if proto == "tuic" else (None,)
    for idx, mode in enumerate(modes):
        suffix = f"-{mode}" if mode else ""
        cA.disconnect_all()
        time.sleep(2)
        ok, ip, clog = _connect(cA, sc, proto, "A", mode, ib=ib)
        if not ok:
            phase.add(SubTest(f"udp-dns{suffix}", Status.SKIP,
                              "account A failed to bring up the tunnel"
                              + (f" in udpRelayMode={mode}" if mode else ""),
                              clog[-1200:]))
            log(f"-> udp-dns{suffix} [skip] tunnel did not come up")
            continue
        fn = _udp_dns_probe(cA, f"udp-dns{suffix}", xraytun_mod.IFACE)
        if mode:
            fn.detail = f"udpRelayMode={mode}: {fn.detail}"
        phase.add(fn)
        log(f"-> {fn.name} [{fn.status.value}] {fn.detail}")
        # Accounting once, on the first (default) mode: the billing path is shared by
        # both carriers, so repeating it would cost a minute and prove nothing new.
        if idx == 0:
            us = _udp_usage_probe(cA, panel, ib)
            phase.add(us)
            log(f"-> {us.name} [{us.status.value}] {us.detail}")
    _disconnect(cA, proto)
    cA.disconnect_all()
    time.sleep(2)


def run(proto: str, cA: Client, cB: Client, cC: Client, sc, cfg: dict, result, panel=None, server_exec=None, mode=None) -> None:
    # MTProto is a relay, not a tunnel: none of the shared suite below applies to it
    # (see _run_mtproto), so it takes its own path rather than threading NA overrides
    # through every check.
    if proto == "mtproto":
        _run_mtproto(cA, cB, cC, sc, result, panel, server_exec, mode or "classic")
        return
    if proto == "mtproto-toggle":
        _run_mtproto_toggle(cA, sc, result, panel, server_exec)
        return
    if proto == "mtproto-termination":
        _run_mtproto_termination(cA, sc, result, panel, server_exec)
        return
    if proto == "mtproto-adtag":
        _run_mtproto_adtag(cA, sc, result, panel, server_exec)
        return
    if proto == "ssh-udp":
        _run_ssh_udp(cA, sc, cfg, result, panel, server_exec)
        return
    # Resolve the target phase, inbound, and account model. ikev2 runs once per auth
    # mode: eap-mschapv2 = the primary 2-account inbound (RADIUS path); psk/eap-tls =
    # their single-account inbound (rbridge-sweep path). Non-ikev2 protocols are unchanged
    # (mode is None -> phase/inbound from PHASE[proto] / sc.inbounds[proto]).
    if proto == "ikev2":
        mode = mode or "eap-mschapv2"
        phase: Phase = result.phase(IKEV2_PHASE_BY_MODE[mode])
        if mode == "eap-mschapv2":
            ib = sc.inbounds.get("ikev2")
            single_account = False
        else:
            ib = (getattr(sc, "ikev2_extra", None) or {}).get(mode)
            single_account = True   # the panel binds a psk/eap-tls inbound to ONE account
        present = ib is not None
    else:
        phase = result.phase(PHASE[proto])
        ib = sc.inbounds.get(proto)
        single_account = False
        present = proto in sc.inbounds
    log = cA.log

    def server_log():
        """Server-side daemon log for this protocol (for connect diagnostics)."""
        if panel is None:
            return ""
        try:
            return "\n\n== server " + proto + " log ==\n" + panel.core_logs(proto)
        except Exception:  # noqa: BLE001
            return ""

    if not present:
        phase.add(SubTest(f"{proto}-inbound", Status.SKIP,
                          "inbound was not created in setup"))
        log(f"-> inbound not created in setup -> skipping suite")
        return

    dns_domain = (cfg.get("dns_resolve") or {}).get("domain", "cloudflare.com")

    # ---- GRE: pin account A's peer, leave account B's dynamic ----------
    # The panel demultiplexes GRE peers two ways and both must be exercised. Account A
    # gets client A's REAL bridge address, so the server builds a point-to-point netdev
    # for it; account B keeps the blank slot it was created with, so it is served by the
    # shared catch-all netdev with a learned reverse path. Doing it here (not in setup) is
    # unavoidable: the client VMs do not exist when the inbound is built.
    if proto == "gre" and panel is not None and ib is not None:
        gp = phase.add(SubTest("peer-provision"))
        try:
            a_ip = gre_mod.lan_ip(cA)
            if not a_ip:
                raise AssertionError("could not read client A's bridge address")
            panel.set_gre_peer(ib.inbound_id, ib.accounts["A"].email, 0, a_ip)
            server_setup._fetch_gre_configs(panel, ib)
            a_cfg = (ib.gre_configs.get("A") or [{}])[0]
            b_cfg = (ib.gre_configs.get("B") or [{}])[0]
            if a_cfg.get("dynamic", True):
                raise AssertionError(f"account A still dynamic after setting peerIp={a_ip}")
            if not b_cfg.get("dynamic", False):
                raise AssertionError("account B should have stayed dynamic (blank peer)")
            gp.status = Status.PASS
            gp.detail = (f"A static peer {a_ip} (point-to-point netdev), "
                         f"B dynamic (catch-all + learner)")
        except Exception as e:  # noqa: BLE001
            gp.status = Status.FAIL
            gp.detail = str(e)[:200]
        log(f"-> {gp.name} [{gp.status.value}] {gp.detail}")

    # ---- connect variants on A (each tested in isolation) --------------
    # Disconnect before AND after every variant so leftover state (e.g. an
    # IPsec SA from the l2tp-ipsec test) can't contaminate the next variant.
    primary_ok = False
    for label, variant, is_primary in _variants(proto):
        if abort.is_set():
            log("-> aborted by user [skip]")
            return
        _disconnect(cA, proto)
        log(f"-> A {label}...")
        st = phase.add(SubTest(label))
        ok, ip, clog = _connect(cA, sc, proto, "A", variant, ib=ib)
        st.log = clog if ok else clog + server_log()
        st.status = Status.PASS if ok else Status.FAIL
        st.detail = f"tunnel ip {ip}" if ok else "connect failed"
        log(f"-> A {label} [{st.status.value}] {st.detail}")
        # per-variant DNS resolution through the tunnel (dig +short). Name it by
        # the variant suffix: connect-udp-new -> dns-resolve-udp-new.
        if ok:
            dns_name = "dns-resolve" + label[len("connect"):]
            dchk = checks.dns_resolve(cA, dns_domain, name=dns_name)
            phase.add(dchk)
            log(f"-> A {dchk.name} [{dchk.status.value}] {dchk.detail}")
        if is_primary:
            primary_ok = ok
        _disconnect(cA, proto)

    # ---- TEST 2: IPsec must NOT be stuck "Stopped" (l2tp/ipsec only) ----
    # L2TP/IPsec (libreswan) can get stuck stopped when GenerateIPsecConfig emits
    # version-wrong keywords; assert it is up when it's expected up (l2tp/ipsec
    # configured + libreswan present). NA when not applicable (no PSK / no
    # libreswan, e.g. Arch). Independent of client state; wrapped so it can't abort.
    if proto == "l2tp":
        try:
            ist = _ipsec_not_stuck(sc.inbounds["l2tp"], panel, server_exec, log)
        except Exception as e:  # noqa: BLE001
            ist = SubTest("ipsec-not-stuck", Status.ERROR, str(e)[:150])
        phase.add(ist)
        log(f"-> {ist.name} [{ist.status.value}] {ist.detail}")

    # ---- GRE encapsulation modes: IPsec-required and FOU ---------------
    # The raw path was just covered by the connect variants above. These two flip the
    # inbound's own switches and re-dial, which is the only way to prove them: both are
    # server-side toggles with no client-visible negotiation.
    if proto == "gre" and panel is not None and ib is not None:
        for st in _gre_mode_checks(cA, sc, ib, panel, log, server_exec):
            phase.add(st)
            log(f"-> {st.name} [{st.status.value}] {st.detail}")
        _disconnect(cA, proto)
        cA.disconnect_all()
        time.sleep(2)

    # Whether the shared check suite can run. The User Limit Strategy test below is
    # INDEPENDENT of it — it reconfigures the inbound (daemon restart = clean slate)
    # — so it always runs, even when the shared suite is skipped (e.g. an intermittent
    # openvpn re-establish failure when the K=2 block is briefly ghost-exhausted).
    suite_ok = primary_ok
    a_primary_ip = ""
    if not primary_ok:
        phase.add(SubTest("suite", Status.SKIP,
                          "primary connection failed; shared checks skipped"))
        log(f"-> primary connect failed -> skipping shared checks (strategy test still runs)")
    else:
        # Bring the primary up fresh for the shared check suite, RETRYING with a full
        # teardown + settle between attempts. Cycling the connect variants just above
        # leaves the daemon mid-teardown of the last variant's session, so an immediate
        # single reconnect can race it freeing the tunnel IP (esp. ocserv releasing the
        # just-used block IP) and intermittently fail — which would wrongly SKIP the
        # entire shared suite (tunnel-egress/internet/dns-leak/user-limit/c2c/routing/
        # cross-inbound) for the phase. The strategy/traffic tests already use this
        # retry (traffic._connect_retry); the shared-suite re-establish was the one
        # connect that didn't, which is why it flaked here and nowhere else.
        ok, a_primary_ip, clog = False, "", ""
        for _ in range(3):
            _disconnect(cA, proto)
            cA.disconnect_all()
            time.sleep(4)
            ok, a_primary_ip, clog = _connect(cA, sc, proto, "A", ib=ib)
            if ok:
                break
        if not ok:
            suite_ok = False
            phase.add(SubTest("suite", Status.SKIP, "could not re-establish primary after retries"))
            log(f"-> could not re-establish primary -> skipping shared checks (strategy test still runs)")

    if suite_ok:
        # ---- shared check suite (A stays connected) --------------------
        # NOTE: the source-IP `routing` check runs later, in the client-to-client
        # block, where BOTH clients are connected (A = freedom, B = blackhole).
        log(f"-> running checks (tunnel-egress, internet, dns-leak)...")
        # Run each check independently: a raising check must not abort the others.
        check_fns = [
            ("tunnel-egress", lambda: checks.tunnel_egress(cA)),
            ("internet", lambda: checks.internet(cA)),
            ("dns-leak", lambda: checks.dns_leak(cA, cfg)),
        ]
        for name, fn in check_fns:
            try:
                chk = fn()
            except Exception as e:  # noqa: BLE001
                chk = SubTest(name, Status.ERROR, str(e)[:150])
            log(f"-> {chk.name} [{chk.status.value}] {chk.detail}")
            phase.add(chk)

        # ---- User Limit: a 2nd device on the SAME account --------------
        # With user_limit K>1 the account owns a block; the 2nd device must get a
        # DISTINCT IP inside that block (A device 1 = cA, still up) and reach the
        # internet. cB is idle here (client-to-client connects it later).
        if proto in ("wg-c", "awg"):
            phase.add(SubTest("user-limit", Status.NA,
                              "WireGuard gateway model: one keypair per account; the block "
                              "(e.g. /29) IS the limit, not per-device enforcement"))
            log("-> user-limit [na] gateway model (one keypair per account)")
        elif proto in XRAY_NATIVE:
            # NOT "skipped": there is no User Limit on these inbounds to exercise. The
            # VPN account-slot User Limit hands an account K consecutive tunnel IPs, and
            # an Xray-native protocol hands out no address at all, so the panel does not
            # offer it. The equivalent cap for them is the CORE's per-account IP limiter
            # (`limitIp`, common/speedlimit, enforced at dispatch admission), a
            # different mechanism on a different code path, which this phase is not
            # wired for: it would need more distinct client source IPs than the rig has
            # VMs to drive past the cap.
            why = ("Xray-native: no per-account IP block to allocate. The device cap for "
                   "these is the core's per-account IP limiter (limitIp), not the VPN "
                   "User Limit, and is not covered by this phase")
            phase.add(SubTest("user-limit", Status.NA, why))
            log(f"-> user-limit [na] {why}")
        elif ib is not None and getattr(ib, "user_limit", 1) > 1:
            _user_limit_check(proto, cA, cB, sc, a_primary_ip, ib, log, phase)

        # ---- client-to-client + routing + cross-inbound (need account B) --
        # These need a SECOND account (B). Single-account modes (ikev2 psk/eap-tls,
        # which the panel binds to exactly one account) have only account A, so they
        # are Not Applicable there (source-IP A/B split is covered by eap-mschapv2).
        if single_account:
            for nm, why in (("client-to-client", "single-account mode: no 2nd account"),
                            ("routing", "single-account mode: no A/B split"),
                            ("cross-inbound", "single-account mode: no 2nd account")):
                phase.add(SubTest(nm, Status.NA, why))
                log(f"-> {nm} [na] {why}")
        elif proto == "ssh":
            # SSH runs the SAME suite as the tunnel protocols MINUS client-to-client and
            # cross-inbound (the user's explicit instruction): a relay has no client
            # tunnel address to ping between clients or across inbounds. Routing STILL
            # runs, and is the meaningful per-client proof here: A (freedom) and B
            # (blackhole) egress through Xray keyed on their socks username (= email), so
            # A reaches the internet and B is cut off with no source IP involved at all.
            log("-> routing (B blackhole alongside A freedom; c2c + cross-inbound N/A for a relay)...")
            cB.disconnect_all()
            time.sleep(2)
            okB, ipB, logB = _connect(cB, sc, proto, "B")
            rt = SubTest("routing")
            if okB:
                try:
                    r = checks.routing(cA, cB)
                    rt.status, rt.detail, rt.log = r.status, r.detail, r.log
                except Exception as e:  # noqa: BLE001
                    rt.status, rt.detail = Status.ERROR, str(e)[:150]
            else:
                rt.status = Status.SKIP
                rt.detail = "peer B (blackhole client) failed to connect"
                rt.log = logB
            log(f"-> routing [{rt.status.value}] {rt.detail}")
            phase.add(rt)
            for nm, why in (
                ("client-to-client",
                 "SSH relay: clients get no tunnel address, so there is nothing to ping "
                 "between them (excluded per spec)"),
                ("cross-inbound",
                 "SSH relay: no tunnel addresses to route between inbounds (excluded per spec)"),
            ):
                phase.add(SubTest(nm, Status.NA, why))
                log(f"-> {nm} [na] {why}")
            _disconnect(cB, proto)
            cB.disconnect_all()
            time.sleep(2)
        elif proto in XRAY_NATIVE:
            # Same shape as the ssh branch above and for the same structural reason: a
            # proxy hands its clients no tunnel address, so there is nothing to ping
            # between two of them or across two inbounds. Routing, by contrast, is the
            # STRONGEST per-client proof in this whole phase: xray attaches the matched
            # account to the session itself, so the panel's `user` rules select the
            # outbound per account with no source-IP translation anywhere in the path.
            # A (freedom) reaches the internet and B (blackhole) is cut off while both
            # sit behind the same inbound, the same port and the same TLS certificate.
            log("-> routing (B blackhole alongside A freedom; c2c + cross-inbound N/A for a proxy)...")
            cB.disconnect_all()
            time.sleep(2)
            okB, ipB, logB = _connect(cB, sc, proto, "B")
            rt = SubTest("routing")
            if okB:
                try:
                    r = checks.routing(cA, cB)
                    rt.status, rt.detail, rt.log = r.status, r.detail, r.log
                except Exception as e:  # noqa: BLE001
                    rt.status, rt.detail = Status.ERROR, str(e)[:150]
            else:
                rt.status = Status.SKIP
                rt.detail = "peer B (blackhole client) failed to connect"
                rt.log = logB
            log(f"-> routing [{rt.status.value}] {rt.detail}")
            phase.add(rt)
            for nm, why in (
                ("client-to-client",
                 f"{proto} is an Xray-native proxy: clients get no tunnel address, so "
                 f"there is nothing to ping between them"),
                ("cross-inbound",
                 f"{proto} is an Xray-native proxy: no tunnel addresses to route between "
                 f"inbounds (the inbound-level gate it would exercise is an IP/nftables "
                 f"gate, which never sees these protocols)"),
            ):
                phase.add(SubTest(nm, Status.NA, why))
                log(f"-> {nm} [na] {why}")
            _disconnect(cB, proto)
            cB.disconnect_all()
            time.sleep(2)
        else:
            # ---- client-to-client (same inbound) ----------------------
            log(f"-> client-to-client (B on same inbound)...")
            c2c = SubTest("client-to-client")
            cB.disconnect_all()          # clean slate on B before its connect
            time.sleep(2)
            okB, ipB, logB = _connect(cB, sc, proto, "B")
            rt = SubTest("routing")
            if okB:
                res = checks.ping_peer("client-to-client", cA, ipB, must_reach=True)
                c2c.status, c2c.detail, c2c.log = res.status, res.detail, res.log
                # source-IP routing proof: A (freedom) is still up, B (blackhole) is up
                # now — assert the split from connectivity while both are connected.
                try:
                    r = checks.routing(cA, cB)
                    rt.status, rt.detail, rt.log = r.status, r.detail, r.log
                except Exception as e:  # noqa: BLE001
                    rt.status, rt.detail = Status.ERROR, str(e)[:150]
            else:
                c2c.status = Status.SKIP
                c2c.detail = "peer B (same protocol) failed to connect"
                c2c.log = logB
                rt.status = Status.SKIP
                rt.detail = "peer B (blackhole client) failed to connect"
            log(f"-> client-to-client [{c2c.status.value}] {c2c.detail}")
            phase.add(c2c)
            log(f"-> routing [{rt.status.value}] {rt.detail}")
            phase.add(rt)
            _disconnect(cB, proto)

            # ---- cross-inbound (peer protocol) ------------------------
            peer = PEER[proto]
            log(f"-> cross-inbound (B on peer '{peer}')...")
            cross = SubTest("cross-inbound")
            if peer not in sc.inbounds:
                cross.status = Status.SKIP
                cross.detail = f"peer inbound '{peer}' not available"
            else:
                # Full teardown on B (esp. strongswan/charon after an l2tp-ipsec run,
                # which otherwise deactivates the fresh ppp0 of the peer protocol),
                # then settle before connecting the peer.
                cB.disconnect_all()
                time.sleep(3)
                okP, ipP, logP = _connect(cB, sc, peer, "B")
                if okP:
                    res = checks.ping_peer("cross-inbound", cA, ipP, must_reach=True)
                    cross.status, cross.detail, cross.log = res.status, res.detail, res.log
                else:
                    cross.status = Status.SKIP
                    cross.detail = f"peer {peer} on B failed to connect"
                    cross.log = logP
                _disconnect(cB, peer)
            log(f"-> cross-inbound [{cross.status.value}] {cross.detail}")
            phase.add(cross)

    # ---- UDP through an Xray-native proxy ------------------------------
    # Independent of the shared suite (it dials its own connections) and placed BEFORE
    # the traffic block, whose termination sub-test disables account A. Wrapped so a
    # raising probe can't abort the phase.
    if proto in XRAY_NATIVE and ib is not None:
        try:
            _xray_udp_checks(proto, cA, sc, ib, panel, log, phase)
        except Exception as e:  # noqa: BLE001
            phase.add(SubTest("udp-dns", Status.ERROR, str(e)[:150]))

    # ---- User Limit Strategy: reject vs accept on a 3rd device ---------
    # Always runs (independent of the shared suite): it restarts the daemon.
    # WireGuard is the exception: an account owns exactly K device keypairs (a peer's
    # key IS its credential), so there is no dynamic (K+1)th-device admission to reject
    # or evict — the cap is structural. The device COUNT and its hard disable/quota
    # enforcement are covered by user-limit / multi-user-total / account-termination.
    if proto in ("wg-c", "awg"):
        for nm in ("strategy-reject", "strategy-accept"):
            phase.add(SubTest(nm, Status.NA,
                              "WireGuard: K device keypairs are structural — no dynamic "
                              "(K+1)th admission to reject/evict"))
            log(f"-> {nm} [na] structural K (no dynamic admission)")
    elif proto == "gre":
        for nm in ("strategy-reject", "strategy-accept"):
            phase.add(SubTest(nm, Status.NA,
                              "GRE: K peer slots are structural (and GRE has no handshake "
                              "or session) — no dynamic (K+1)th admission to reject/evict"))
            log(f"-> {nm} [na] structural K (no admission event)")
    elif proto in XRAY_NATIVE:
        for nm in ("strategy-reject", "strategy-accept"):
            phase.add(SubTest(nm, Status.NA,
                              "Xray-native: the User Limit Strategy is a property of the VPN "
                              "account-slot allocator, which these inbounds do not have (see "
                              "user-limit); there is no (K+1)th slot to reject or evict"))
            log(f"-> {nm} [na] no VPN account-slot allocator")
    elif proto == "ssh" and ib is not None and getattr(ib, "user_limit", 1) > 1 and panel is not None:
        _ssh_strategy_check(cA, cB, cC, sc, ib, panel, log, phase)
    elif ib is not None and getattr(ib, "user_limit", 1) > 1 and panel is not None:
        _strategy_check(proto, cA, cB, cC, sc, ib, panel, log, phase, server_exec)

    # ---- WireGuard / AmneziaWG preshared-key mode ----------------------
    # Prove the optional PSK mode works end-to-end: a separate psk-enabled wgc/awg
    # inbound, a real handshake + internet through it, then tear it down. Covers "with
    # and without preshared key" (the primary suite above ran the no-PSK path). awg runs
    # the identical check against its OWN protocol (module/inbound), not wg-c's.
    if proto in ("wg-c", "awg") and panel is not None:
        try:
            pk = _wgc_psk_check(cC, sc, panel, log, proto=proto)
        except Exception as e:  # noqa: BLE001
            pk = SubTest("psk-mode", Status.ERROR, str(e)[:150])
        phase.add(pk)
        log(f"-> {pk.name} [{pk.status.value}] {pk.detail}")
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)

    # ---- OpenConnect same-NAT device limit -----------------------------
    # Two devices on ONE account from ONE source IP (two phones on home wifi). ocserv
    # sends no NAS-Port, so both share a Calling-Station-Id — the E2E's separate client
    # VMs have distinct IPs and can't hit this, so cA opens a SECOND tunnel (tun1)
    # itself. Each device must get a DISTINCT routable block IP; the idempotent-redial
    # cache used to collapse them onto one IP → 2nd device no internet (the real report).
    if proto == "openconnect" and ib is not None and getattr(ib, "user_limit", 1) > 1:
        _oc_same_nat_check(cA, sc, ib, log, phase, server_exec)

    # ---- GRE: informational nft/data-plane dump ------------------------
    # Recorded as NA (it asserts nothing) purely so every run carries the counters needed
    # to tell a GRE-specific drop from an upstream problem. Without it the first
    # "tunnel up, gateway reachable, no internet" failure had to be diagnosed by guesswork.
    if proto == "gre" and server_exec is not None:
        dump = SubTest("gre-nft-counters", Status.NA, "informational")
        try:
            parts = []
            for label, cmd in (
                    ("gre rules in prerouting",
                     "nft -a list chain ip vpn prerouting 2>&1 | grep -E 'gre-antispoof|gre-blocked|10\\.9\\.' || echo none"),
                    ("gre accounting counters",
                     "nft list chain ip vpn gre_acct_in 2>&1 | head -20; nft list chain ip vpn gre_acct_out 2>&1 | head -20"),
                    ("gre devices", "ip -d link show type gre 2>&1 | grep -E '^[0-9]+:|gre remote'"),
                    ("gre routes/neigh",
                     "ip route show | grep '10\\.9\\.'; "
                     "for d in $(ip -o link show type gre | sed 's/^[0-9]*: //; s/@.*//'); do "
                     "echo \"-- $d\"; ip neigh show dev \"$d\"; done"),
                    ("xray dokodemo listeners", "ss -lntp 2>/dev/null | grep -E ':123[0-9][0-9]' || echo none"),
            ):
                _, o, _ = server_exec(cmd, timeout=25)
                parts.append(f"== {label} ==\n{str(o)[:1200]}")
            dump.log = "\n".join(parts)
        except Exception as e:  # noqa: BLE001
            dump.log = f"(capture failed: {e})"
        phase.add(dump)
        log(f"-> {dump.name} [na] captured")

    # ---- User Limit: traffic AGGREGATION across the account's devices --
    # Prove the account's counted traffic is the SUM over its K simultaneous
    # devices, not per-device / not just one. Runs AFTER the strategy check (which
    # leaves a clean all-down slate) and BEFORE the usage/termination block (which
    # resets the counter fresh and, in termination, DISABLES account A — so this
    # must precede it). Independent of the shared suite; wrapped so a raising test
    # can't abort the phase.
    if proto == "gre":
        phase.add(SubTest("multi-user-total", Status.NA,
                          "GRE gateway model: the account's peers share one billed block, "
                          "so there is no per-peer split to aggregate"))
    elif proto in ("wg-c", "awg"):
        phase.add(SubTest("multi-user-total", Status.NA,
                          "WireGuard gateway model: one keypair per account, no per-device "
                          "traffic split to aggregate"))
        log("-> multi-user-total [na] gateway model (one keypair per account)")
    elif proto in XRAY_NATIVE:
        # The test it would run asserts that K per-device tunnel IPs fold onto ONE
        # account total. These protocols never split an account across device IPs in the
        # first place (every session of an account is already billed to the one email on
        # the session), so there is nothing to aggregate. That the email-keyed counter
        # moves at all is what `account-usage` below proves.
        why = ("Xray-native: sessions are billed to the account email directly, with no "
               "per-device IP split to aggregate (see user-limit)")
        phase.add(SubTest("multi-user-total", Status.NA, why))
        log(f"-> multi-user-total [na] {why}")
    elif ib is not None and getattr(ib, "user_limit", 1) > 1 and panel is not None:
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)
        mu_clients = [cA, cB, cC]
        # per-client closure -> all connect onto the SAME account "A" (device 1..N)
        mu_connect = [(lambda c=c: _connect(c, sc, proto, "A", ib=ib)) for c in mu_clients]
        try:
            mu = traffic.multi_user_total(mu_clients, panel, ib, cfg, mu_connect, log,
                                          server_exec=server_exec)
        except Exception as e:  # noqa: BLE001
            mu = SubTest("multi-user-total", Status.ERROR, str(e)[:150])
        log(f"-> {mu.name} [{mu.status.value}] {mu.detail}")
        phase.add(mu)
        for c in (cA, cB, cC):
            _disconnect(c, proto)
            c.disconnect_all()
        time.sleep(2)

    # ---- TEST 1: multiple inbounds of the SAME protocol ----------------
    # Prove the panel supports 2+ inbounds of one protocol at once. Independent of
    # the shared suite (it builds & tears down its OWN 2nd inbound). Runs BEFORE the
    # traffic block, which disables account A on the primary. Wrapped so a raising
    # test can't abort the phase.
    if single_account:
        phase.add(SubTest("multi-inbound-same-proto", Status.NA,
                          "single-account mode: covered by the eap-mschapv2 phase"))
        log("-> multi-inbound-same-proto [na] single-account mode")
    elif panel is not None:
        try:
            mi = _multi_inbound_check(proto, cA, cB, cC, sc, panel, log)
        except Exception as e:  # noqa: BLE001
            mi = SubTest("multi-inbound-same-proto", Status.ERROR, str(e)[:150])
        phase.add(mi)
        log(f"-> {mi.name} [{mi.status.value}] {mi.detail}")
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)

    # ---- traffic accounting: usage counting + termination on limit -----
    # Runs LAST on account A (freedom-routed) — it burns/limits A, which is
    # disposable now that every other check is done. Each drives real traffic
    # through the tunnel and reads the panel's counter back.
    if ib is not None and panel is not None:
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)
        connect_A = lambda: _connect(cA, sc, proto, "A", ib=ib)  # noqa: E731
        u = traffic.usage(cA, panel, ib, cfg, connect_A, log, server_exec=server_exec)
        log(f"-> {u.name} [{u.status.value}] {u.detail}")
        phase.add(u)
        _disconnect(cA, proto)
        cA.disconnect_all()
        time.sleep(2)
        # Traffic Multiplier lives at the accounting layer, below every protocol's
        # collector, so it has to be proven per protocol rather than once. Between
        # usage and termination: it resets A's counter on the way out, which
        # termination re-establishes anyway.
        m = traffic.multiplier(cA, panel, ib, cfg, connect_A, log, server_exec=server_exec)
        log(f"-> {m.name} [{m.status.value}] {m.detail}")
        phase.add(m)
        _disconnect(cA, proto)
        cA.disconnect_all()
        time.sleep(2)
        t = traffic.termination(cA, panel, ib, cfg, connect_A, log)
        log(f"-> {t.name} [{t.status.value}] {t.detail}")
        phase.add(t)

    # (ikev2 psk/eap-tls now run their OWN full suite via run(mode=...), one phase per
    # mode — the old connect-only smoke block here is gone.)
    _disconnect(cA, proto)


def _user_limit_check(proto, cA, cB, sc, a_primary_ip, ib, log, phase) -> None:
    """Prove per-account User Limit blocks: a 2nd device on account A (on cB,
    while A's 1st device on cA stays up) gets a DISTINCT IP inside A's aligned
    block and reaches the internet. This exercises the runtime allocator (RADIUS
    free-list for l2tp/pptp, connect-hook lease for openvpn)."""
    ul = SubTest("user-limit")
    log(f"-> user-limit (2nd device on account A, K={ib.user_limit})...")
    cB.disconnect_all()
    time.sleep(2)
    ok2, ip2, log2 = _connect(cB, sc, proto, "A", ib=ib)  # SAME account A -> device 2
    if proto == "ssh":
        # SSH is a relay: an account owns no IP block, so "2nd device gets a distinct
        # block IP" does not apply. K counts DISTINCT client source IPs, so the proof is:
        # a 2nd device (a different client VM = a different source IP) is admitted under
        # K=2 and reaches the internet alongside device 1, both egressing as account A.
        try:
            c1 = checks.internet(cA)
            c2 = checks.internet(cB) if (ok2 and ip2) else None
            both = c2 is not None and c1.status == Status.PASS and c2.status == Status.PASS
            ul.log = (f"device1 {a_primary_ip} net1={c1.status.value}\n"
                      f"device2 conn={ok2} ip={ip2!r} net2={(c2.status.value if c2 else 'n/a')}\n"
                      f"{log2[-300:]}")
            if not ok2 or not ip2:
                ul.status, ul.detail = Status.FAIL, "2nd device failed to connect"
            elif both:
                ul.status = Status.PASS
                ul.detail = (f"2 devices (distinct source IPs) on 1 account under K="
                             f"{ib.user_limit}, both online via per-client socks routing")
            else:
                ul.status = Status.FAIL
                ul.detail = (f"2nd device up but not both online "
                             f"(net1={c1.status.value} net2={(c2.status.value if c2 else 'n/a')})")
        except Exception as e:  # noqa: BLE001
            ul.status, ul.detail = Status.ERROR, str(e)[:150]
        log(f"-> user-limit [{ul.status.value}] {ul.detail}")
        phase.add(ul)
        _disconnect(cB, proto)
        cB.disconnect_all()
        time.sleep(2)
        return
    try:
        if not ok2 or not ip2:
            ul.status, ul.detail, ul.log = Status.FAIL, "2nd device failed to connect", log2
        elif ip2 == a_primary_ip:
            ul.status = Status.FAIL
            ul.detail = f"both devices got the SAME ip {ip2} (block allocation broken)"
        else:
            # Account A's K device IPs are a CONSECUTIVE [base, base+K) range in one
            # /24. device1 (a_primary_ip) connected first so it holds the block BASE
            # — derive the expected range from the ACTUAL device1 IP rather than
            # recomputing it (the inbound id is NOT the range's third octet in
            # general: nextFreeSubnet may pick a different /24).
            prefix3, base_str = a_primary_ip.rsplit(".", 1)
            base = int(base_str)
            block = {f"{prefix3}.{base + d}" for d in range(ib.user_limit)}
            rng = f"{prefix3}.{base}..{prefix3}.{base + ib.user_limit - 1}"
            d2_in = ip2 in block
            c1 = checks.internet(cA)
            c2 = checks.internet(cB)
            both = c1.status == Status.PASS and c2.status == Status.PASS
            ul.log = (f"device1 {a_primary_ip} (block base)\ndevice2 {ip2} in [{rng}]={d2_in}\n"
                      f"net1={c1.status.value} net2={c2.status.value}\n{c2.log}")
            if d2_in and both:
                ul.status = Status.PASS
                ul.detail = f"2 devices on 1 account (K={ib.user_limit}): {a_primary_ip} + {ip2} in [{rng}], both online"
            else:
                ul.status = Status.FAIL
                ul.detail = (f"d1={a_primary_ip} d2={ip2}(in={d2_in}) "
                             f"net1={c1.status.value} net2={c2.status.value}")
    except Exception as e:  # noqa: BLE001
        ul.status, ul.detail = Status.ERROR, str(e)[:150]
    log(f"-> user-limit [{ul.status.value}] {ul.detail}")
    phase.add(ul)
    _disconnect(cB, proto)
    cB.disconnect_all()
    time.sleep(2)


def _strategy_check(proto, cA, cB, cC, sc, ib, panel, log, phase, server_exec=None) -> None:
    """Prove the User Limit Strategy on a K=2 account. With 2 devices already up
    (cA=device1/oldest, cB=device2), a 3rd device (cC) is:
      - REJECTED under strategy="reject" (cC never gets a working tunnel), and
      - ADMITTED under strategy="accept", which disconnects the OLDEST device (cA).
    The inbound is reconfigured in place between the two sub-tests; the panel's
    on<Proto>Changed hook regenerates config + restarts the daemon (clean slate).

    Eviction detection differs by protocol:
      - l2tp/pptp: cA's tunnel interface DROPS (the ppp link is torn down and the
        CLI client does not auto-redial) — watched in a background thread.
      - openvpn: the client keeps tun0 up (persist-tun) and auto-reconnects, so the
        client side can't see the drop. Instead assert SERVER-SIDE that the account
        never exceeds K live sessions: the status file's CLIENT_LIST count stays <=K
        when the oldest was evicted, vs 3 (a duplicate) when it was not."""
    iface = "tun0" if proto in ("openvpn", "openconnect") else "ppp0"

    def all_down():
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)

    def watch_drop(c, window=30):
        """Poll c's tunnel iface in a background thread for the whole duration of
        the 3rd device's connect. Returns (thread, flag); flag['v'] becomes True
        the instant the iface loses its IP — the server-side eviction — even if an
        OpenVPN client then auto-reconnects and brings the iface back seconds later
        (which a single post-connect check would miss)."""
        flag = {"v": False}

        def _poll():
            end = time.monotonic() + window
            while time.monotonic() < end and not flag["v"]:
                if not c.wait_iface(iface, timeout=1):
                    flag["v"] = True
                    return
                time.sleep(1)

        th = threading.Thread(target=_poll, daemon=True)
        th.start()
        return th, flag

    # ---------- strategy = reject ----------
    log(f"-> user-limit-strategy REJECT (K={ib.user_limit})...")
    rj = phase.add(SubTest("strategy-reject"))
    try:
        all_down()
        panel.set_user_limit_strategy(ib.inbound_id, "reject")
        time.sleep(6)  # daemon restart + config apply
        ok1, ip1, _ = _connect(cA, sc, proto, "A", ib=ib)
        time.sleep(2)
        ok2, ip2, _ = _connect(cB, sc, proto, "A", ib=ib)
        time.sleep(2)
        ok3, ip3, clog3 = _connect(cC, sc, proto, "A", ib=ib)  # 3rd device must be refused
        n3 = checks.internet(cC) if ok3 else None
        admitted = ok3 and n3 is not None and n3.status == Status.PASS

        # Causation: with K == the account's block size, a 3rd device is unroutable even
        # with NO cap, so "3rd didn't reach the internet" proves nothing on its own.
        # Assert the SERVER actively refused it. l2tp/pptp: the in-panel RADIUS logs an
        # explicit user-limit rejection. openvpn: the account must NOT gain a 3rd live
        # session (an over-admit would show K+1 CLIENT_LIST rows inside its block).
        refused = False
        sig = ""
        if proto == "openvpn":
            rows = _ovpn_status_rows(server_exec, ib.inbound_id, "udp")
            live = 0
            if ip1:
                p3, b = ip1.rsplit(".", 1)
                block = {f"{p3}.{int(b) + d}" for d in range(ib.user_limit)}
                live = sum(1 for r in rows if len(r) > 3 and r[3] in block)
            refused = 0 < live <= ib.user_limit
            sig = f"live_sessions={live} (cap K={ib.user_limit})"
        else:
            if server_exec is not None:
                try:
                    _, rlog, _ = server_exec(
                        "journalctl -u vpn-ui-panel --no-pager 2>/dev/null | "
                        "grep 'user-limit reached' | tail -1")
                    refused = "user-limit reached" in (rlog or "")
                except Exception:  # noqa: BLE001
                    pass
            sig = f"radius_reject_logged={refused}"

        rj.log = (f"dev1={ok1}/{ip1} dev2={ok2}/{ip2}\n"
                  f"dev3 conn={ok3}/{ip3} net={(n3.status.value if n3 else 'n/a')} | {sig}\n{clog3[-400:]}")
        if ok1 and ok2 and not admitted and refused:
            rj.status = Status.PASS
            rj.detail = f"2 devices up; 3rd actively refused [{sig}]"
        else:
            rj.status = Status.FAIL
            rj.detail = f"expected 3rd actively refused; dev1={ok1} dev2={ok2} admitted={admitted} {sig}"
    except Exception as e:  # noqa: BLE001
        rj.status, rj.detail = Status.ERROR, str(e)[:150]
    log(f"-> strategy-reject [{rj.status.value}] {rj.detail}")

    # ---------- strategy = accept ----------
    log(f"-> user-limit-strategy ACCEPT (K={ib.user_limit})...")
    ac = phase.add(SubTest("strategy-accept"))
    try:
        all_down()
        panel.set_user_limit_strategy(ib.inbound_id, "accept")
        time.sleep(6)
        ok1, ip1, _ = _connect(cA, sc, proto, "A", ib=ib)   # device1 = oldest
        time.sleep(5)                                # firmly establish (must be evictable)
        ok2, ip2, _ = _connect(cB, sc, proto, "A", ib=ib)   # device2
        time.sleep(4)
        if proto == "openvpn":
            # Server-side, churn-proof: capture cA's ORIGINAL session client-id, then
            # assert it's gone after cC joins. persist-tun + auto-reconnect mean cA's
            # tunnel stays up client-side and cA may reconnect with a NEW id, but its
            # original session being killed is the eviction. (A raw session count is
            # unstable during the reconnect war.)
            rows_before = _ovpn_status_rows(server_exec, ib.inbound_id, "udp")
            victim_cid = _ovpn_cid_at_ip(rows_before, ip1)
            ok3, ip3, clog3 = _connect(cC, sc, proto, "A", ib=ib)  # device3: admitted, evicts oldest
            # The detached evictor kills the victim ~1.5s after the connect hook returns,
            # but OpenVPN only rewrites the status file on a FIXED 5s timer (unanchored to
            # the kill), so the victim's ORIGINAL client-id can linger in the file for up to
            # one refresh past the kill. A single read at +6s races that timer. Poll for the
            # cid's disappearance instead (up to ~18s = 3+ refreshes). A monotonic client-id
            # never returns once killed (a reconnect gets a NEW id), and eviction that never
            # fired keeps the cid present through every poll — so this can't mask over-admit.
            still = True
            for _ in range(9):
                time.sleep(2)
                still = _ovpn_cid_present(
                    _ovpn_status_rows(server_exec, ib.inbound_id, "udp"), victim_cid)
                if victim_cid != "" and not still:
                    break
            evicted = ok3 and victim_cid != "" and not still
            evwhy = f"cA orig client-id={victim_cid or '?'} present_after={still} (absent ⇒ evicted)"
        else:
            # Client-side: watch cA's tunnel drop, starting BEFORE cC connects (the
            # eviction fires during cC's connect). The l2tp CLI client has no LCP-echo
            # keepalive, so it can be slow to tear ppp0 down after the server kills its
            # end — making the client-side drop RACE-prone. So ALSO corroborate the
            # eviction SERVER-SIDE: the RADIUS service logs "evicted oldest device
            # proto=<p>" exactly when accept-strategy kicks a device. That log line is
            # a churn-proof fact regardless of when the client notices the drop. Pass
            # if EITHER signal fires (the product really evicted).
            watcher, dropped = watch_drop(cA)
            ok3, ip3, clog3 = _connect(cC, sc, proto, "A", ib=ib)  # device3: admitted, evicts oldest
            watcher.join(timeout=18)
            server_evicted = False
            if server_exec is not None:
                try:
                    _, ev, _ = server_exec(
                        "journalctl -u vpn-ui-panel --no-pager 2>/dev/null | "
                        "grep 'evicted oldest device' | grep 'proto=%s' | tail -1" % proto)
                    server_evicted = "evicted oldest device" in (ev or "")
                except Exception:  # noqa: BLE001
                    pass
            # Causative corroboration: eviction tears down the victim's ppp link on the
            # SERVER (killPPPByIP deletes the interface whose peer is dev1's IP), so that
            # IP must no longer be present on any server ppp interface. This is a
            # churn-proof data-plane fact — unlike the log line alone (which could fire
            # without the link dropping) or the race-prone client-side poll.
            link_gone = None
            if server_exec is not None and ip1:
                try:
                    _, addrs, _ = server_exec(
                        "ip -o addr show 2>/dev/null | grep 'peer %s/' || true" % ip1)
                    link_gone = (addrs or "").strip() == ""
                except Exception:  # noqa: BLE001
                    pass
            # Pass requires the eviction to have actually happened, proven server-side by
            # the churn-proof RADIUS "evicted oldest device" log (server_evicted): the panel
            # emits it only after deleting the victim's session AND killing its link. That is
            # CORROBORATED by the victim's tunnel really dropping — but accept-strategy REUSES
            # the victim's IP for the incoming device, so the server-side `peer <ip>/` probe
            # (link_gone) reads False the instant dev3 takes that IP over — a false negative,
            # not a lingering victim. So accept EITHER corroboration: the victim's client-side
            # drop (authoritative for openconnect — DPD tears tun0 down within seconds; the
            # race-prone fallback for the keepalive-less l2tp CLI) OR the server link gone.
            if server_exec is not None:
                evicted = server_evicted and (dropped["v"] or link_gone is not False)
            else:
                evicted = dropped["v"]
            evwhy = (f"dev1 dropped(client)={dropped['v']} server-evicted={server_evicted} "
                     f"link_gone={link_gone}")
        ac.log = (f"dev1={ok1}/{ip1} dev2={ok2}/{ip2}\n"
                  f"dev3 conn={ok3}/{ip3}\n{evwhy}\n{clog3[-400:]}")
        if ok1 and ok2 and ok3 and evicted:
            ac.status = Status.PASS
            ac.detail = f"3rd admitted ({ip3}); oldest device (dev1) disconnected [{evwhy}]"
        else:
            ac.status = Status.FAIL
            ac.detail = (f"admitted(conn)={ok3} evicted={evicted} "
                         f"(dev1={ok1} dev2={ok2}; {evwhy})")
    except Exception as e:  # noqa: BLE001
        ac.status, ac.detail = Status.ERROR, str(e)[:150]
    log(f"-> strategy-accept [{ac.status.value}] {ac.detail}")

    all_down()


def _ssh_strategy_check(cA, cB, cC, sc, ib, panel, log, phase) -> None:
    """SSH User-Limit strategy on a K=2 account. A "device" is a distinct client source
    IP, which here means a distinct client VM. With 2 devices up (cA=device1/oldest,
    cB=device2), a 3rd device (cC) is:
      - REJECTED under strategy="reject": the SSH server refuses cC's session, so it never
        gets a working SOCKS tunnel and cannot reach the internet. Causative for a relay:
        UNLIKE a tunnel protocol (where a 3rd device is unroutable even with NO cap because
        the account's IP block is exhausted), an SSH 3rd device WOULD egress fine as
        account A with no cap, so "refused / no internet" can only come from the cap.
      - ADMITTED under strategy="accept", which EVICTS the oldest device (cA): the server
        closes cA's SSH connection, so cA's `ssh -N` process exits and its tunnel dies.

    The inbound's strategy is flipped in place via the panel between the two sub-tests
    (the on-ssh-changed hook reconciles the listeners); each sub-test starts from an
    all-down slate."""
    def all_down():
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)

    def ssh_alive(c) -> bool:
        _, out = c.sh("kill -0 $(cat /run/ssh-vpn.pid 2>/dev/null) 2>/dev/null "
                      "&& echo ALIVE || echo DEAD")
        return "ALIVE" in out

    # ---------- strategy = reject ----------
    log(f"-> user-limit-strategy REJECT (ssh, K={ib.user_limit})...")
    rj = phase.add(SubTest("strategy-reject"))
    try:
        all_down()
        panel.set_user_limit_strategy(ib.inbound_id, "reject")
        time.sleep(6)  # listener reconcile + apply
        ok1, ip1, _ = _connect(cA, sc, "ssh", "A", ib=ib)   # device1
        time.sleep(2)
        ok2, ip2, _ = _connect(cB, sc, "ssh", "A", ib=ib)   # device2 (K reached)
        time.sleep(2)
        ok3, ip3, clog3 = _connect(cC, sc, "ssh", "A", ib=ib)  # device3 must be refused
        # Guard: when the SSH session is refused, cC has NO tunnel, so a bare internet
        # check would pass via its PHYSICAL route. Only probe when ok3 (a tunnel came up),
        # so "no internet" means the tunnel is up but the server refuses to forward.
        n3 = checks.internet(cC) if ok3 else None
        admitted = ok3 and n3 is not None and n3.status == Status.PASS
        rj.log = (f"dev1={ok1}/{ip1} dev2={ok2}/{ip2}\n"
                  f"dev3 conn={ok3}/{ip3} net={(n3.status.value if n3 else 'no-tunnel')}\n{clog3[-400:]}")
        if ok1 and ok2 and not admitted:
            rj.status = Status.PASS
            rj.detail = (f"2 devices up; 3rd refused (conn={ok3}, "
                         f"net={(n3.status.value if n3 else 'no-tunnel')}) - K enforced")
        else:
            rj.status = Status.FAIL
            rj.detail = f"expected 3rd refused; dev1={ok1} dev2={ok2} admitted={admitted}"
    except Exception as e:  # noqa: BLE001
        rj.status, rj.detail = Status.ERROR, str(e)[:150]
    log(f"-> strategy-reject [{rj.status.value}] {rj.detail}")

    # ---------- strategy = accept ----------
    log(f"-> user-limit-strategy ACCEPT (ssh, K={ib.user_limit})...")
    ac = phase.add(SubTest("strategy-accept"))
    try:
        all_down()
        panel.set_user_limit_strategy(ib.inbound_id, "accept")
        time.sleep(6)
        ok1, ip1, _ = _connect(cA, sc, "ssh", "A", ib=ib)   # device1 = oldest
        time.sleep(5)                                        # firmly establish (evictable)
        ok2, ip2, _ = _connect(cB, sc, "ssh", "A", ib=ib)   # device2
        time.sleep(4)
        a_alive_before = ssh_alive(cA)
        ok3, ip3, clog3 = _connect(cC, sc, "ssh", "A", ib=ib)  # device3: admitted, evicts oldest
        # Eviction closes cA's SSH connection, so its `ssh -N` exits. Poll for that (up to
        # ~20s) and corroborate with cA losing its tunnel internet (the SOCKS backend is
        # gone, so curl through tun0 fails). A monotonic `ssh -N` never respawns, so this
        # cannot flap back to "alive" and mask a non-eviction.
        a_dead = False
        for _ in range(10):
            time.sleep(2)
            if not ssh_alive(cA):
                a_dead = True
                break
        a_net = checks.internet(cA)
        a_internet_gone = a_net.status != Status.PASS
        evicted = ok3 and a_alive_before and (a_dead or a_internet_gone)
        ac.log = (f"dev1={ok1}/{ip1} dev2={ok2}/{ip2}\n"
                  f"dev3 conn={ok3}/{ip3}\n"
                  f"cA ssh alive_before={a_alive_before} dead_after={a_dead} "
                  f"internet_after={a_net.status.value}\n{clog3[-400:]}")
        if ok1 and ok2 and ok3 and evicted:
            ac.status = Status.PASS
            ac.detail = (f"3rd admitted ({ip3}); oldest device (cA) evicted "
                         f"(ssh_dead={a_dead} internet_gone={a_internet_gone})")
        else:
            ac.status = Status.FAIL
            ac.detail = (f"admitted(conn)={ok3} evicted={evicted} "
                         f"(dev1={ok1} dev2={ok2} alive_before={a_alive_before}; "
                         f"ssh_dead={a_dead} net_gone={a_internet_gone})")
    except Exception as e:  # noqa: BLE001
        ac.status, ac.detail = Status.ERROR, str(e)[:150]
    log(f"-> strategy-accept [{ac.status.value}] {ac.detail}")

    all_down()


def _oc_same_nat_check(cA, sc, ib, log, phase, server_exec=None):
    """Two OpenConnect devices on ONE account from ONE source IP (same VM → same
    Calling-Station-Id; ocserv sends no NAS-Port). Each must get a DISTINCT block IP.
    The idempotent-redial cache used to collapse them onto one IP so the 2nd device
    got no routable address / never came up — the reported "new client no internet"."""
    st = phase.add(SubTest("same-nat-limit"))
    log(f"-> same-nat-limit (2 devices on account A, ONE source IP, K={ib.user_limit})...")
    try:
        cA.disconnect_all()
        cA.sh("pkill -f openconnect 2>/dev/null; true")
        time.sleep(3)
        ok1, ip1, _ = oc_mod.connect(cA, ib, "A", variant="dtls",
                                     server_ip=sc.server_ip, iface="tun0",
                                     keep_existing=False)
        time.sleep(3)
        ok2, ip2, log2 = oc_mod.connect(cA, ib, "A", variant="dtls",
                                        server_ip=sc.server_ip, iface="tun1",
                                        keep_existing=True)
        time.sleep(3)
        ip1_now = cA.wait_iface("tun0", timeout=5)
        ip2_now = cA.wait_iface("tun1", timeout=5)
        distinct = bool(ok1 and ok2 and ip1_now and ip2_now and ip1_now != ip2_now)
        # server-side evidence: the two Access-Accept IPs the panel handed out.
        srv = ""
        if server_exec is not None:
            try:
                _, srv, _ = server_exec(
                    "journalctl -u vpn-ui-panel --no-pager 2>/dev/null | "
                    "grep 'auth accepted (PAP)' | grep 'nas=openconnect' | tail -4")
            except Exception:  # noqa: BLE001
                pass
        st.log = (f"dev1 tun0={ip1_now!r} dev2 tun1={ip2_now!r} distinct={distinct}\n"
                  f"server auth log:\n{srv}\n{log2[-400:]}")
        if distinct:
            st.status = Status.PASS
            st.detail = (f"2 same-NAT devices on 1 account each got a DISTINCT IP "
                         f"({ip1_now}, {ip2_now}) — no idempotent-redial collapse")
        else:
            st.status = Status.FAIL
            st.detail = (f"same-NAT COLLAPSE: dev1={ip1_now!r} dev2={ip2_now!r} "
                         f"(ok1={ok1} ok2={ok2}) — 2nd device didn't get a distinct IP")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    finally:
        cA.sh("pkill -f openconnect 2>/dev/null; true")
        time.sleep(1)
    log(f"-> same-nat-limit [{st.status.value}] {st.detail}")


def _gre_mode_checks(cA, sc, ib, panel, log, server_exec=None) -> list:
    """Prove GRE's two optional encapsulation modes end to end, then restore raw mode.

    ipsec-required: flip ipsecEnable on and allowRaw OFF, so the server accepts protocol
    47 only inside an ESP SA. Then check BOTH halves, because either alone is a false
    pass: a bare tunnel must now FAIL (proving the drop rule bites) and an
    IPsec-negotiated one must SUCCEED (proving the SA and charon config are right). A
    test that only checked the second half would pass even with the gate disabled.

    fou: flip FOU on and dial with UDP encapsulation, which is the only path available to
    a peer behind a NAT that drops protocol 47.
    """
    out = []
    settings = None
    try:
        settings = panel.get_inbound(ib.inbound_id)
    except Exception as e:  # noqa: BLE001
        out.append(SubTest("gre-ipsec-mode", Status.ERROR, f"read inbound: {str(e)[:150]}"))
        return out

    def _set(**changes):
        panel.patch_gre_settings(ib.inbound_id, **changes)
        server_setup._fetch_gre_configs(panel, ib)
        time.sleep(6)   # let the panel rewrite charon/nft and reconcile the data plane

    # Server-side evidence, so an IPsec failure is attributable instead of a bare "no SA".
    # The first run of this test could not distinguish "the panel never configured charon"
    # from "charon is configured but never answered", which are opposite bugs.
    SWANCTL = "/usr/libexec/vpn-ui-strongswan/sbin/swanctl"

    def _server_ipsec_state():
        if server_exec is None:
            return "(no server_exec available)"
        parts = []
        for label, cmd in (
                ("conf.d", "ls -la /etc/swanctl/conf.d/ 2>&1"),
                ("gre conf", "cat /etc/swanctl/conf.d/gre-*.conf 2>&1"),
                ("list-conns", f"{SWANCTL} --list-conns 2>&1 || swanctl --list-conns 2>&1"),
                ("list-sas", f"{SWANCTL} --list-sas 2>&1 || swanctl --list-sas 2>&1"),
                ("udp 500/4500 listeners", "ss -lunp 2>/dev/null | grep -E ':(500|4500)' || echo none"),
                ("charon process", "ps aux | grep -c '[c]haron'"),
                ("nft input chain", "nft list chain ip vpn input 2>&1 | head -20"),
        ):
            try:
                _, out, _ = server_exec(cmd, timeout=25)
            except Exception as e:  # noqa: BLE001
                out = f"(failed: {e})"
            parts.append(f"== server {label} ==\n{str(out)[:900]}")
        try:
            parts.append("== server ipsec core log ==\n" + (panel.core_logs("ipsec") or "")[-2500:])
        except Exception as e:  # noqa: BLE001
            parts.append(f"== server ipsec core log == (failed: {e})")
        return "\n".join(parts)

    # ---- Did the PANEL configure charon at all? ------------------------
    # Independent of the test client's own strongSwan, so a failure here is squarely a
    # product bug and a pass here narrows any later failure to the negotiation itself.
    conn_st = SubTest("gre-ipsec-conn")
    try:
        _set(ipsecEnable=True, allowRaw=False)
        loaded = ""
        if server_exec is not None:
            _, loaded, _ = server_exec(
                f"{SWANCTL} --list-conns 2>&1 || swanctl --list-conns 2>&1", timeout=25)
        want = f"gre-{ib.inbound_id}"
        if server_exec is None:
            conn_st.status, conn_st.detail = Status.NA, "no server_exec available"
        elif want in str(loaded):
            conn_st.status = Status.PASS
            conn_st.detail = f"charon loaded connection {want}"
        else:
            conn_st.status = Status.FAIL
            conn_st.detail = f"charon has no connection {want} after enabling IPsec"
        conn_st.log = str(loaded)[:1500] + "\n\n" + _server_ipsec_state()
    except Exception as e:  # noqa: BLE001
        conn_st.status, conn_st.detail = Status.ERROR, str(e)[:200]
    out.append(conn_st)

    # ---- IPsec required ------------------------------------------------
    st = SubTest("gre-ipsec-mode")
    try:
        gre_mod.disconnect(cA)
        raw_ok, _, raw_log = gre_mod.connect(cA, ib, "A", server_ip=sc.server_ip, mode="raw")
        gre_mod.disconnect(cA)
        sec_ok, _, sec_log = gre_mod.connect(cA, ib, "A", server_ip=sc.server_ip, mode="ipsec")
        gre_mod.disconnect(cA)
        if raw_ok:
            st.status = Status.FAIL
            st.detail = "bare GRE still passed while IPsec was required (drop rule missing)"
            st.log = raw_log
        elif not sec_ok:
            st.status = Status.FAIL
            # Distinguish the two very different causes: charon never negotiating an SA
            # (config/proposal problem) versus an established SA that carries nothing
            # (policy/traffic-selector problem). Reporting one message for both made the
            # first failure of this test undiagnosable from the summary.
            if "never reached INSTALLED" in sec_log:
                st.detail = "no IPsec SA was established (charon never installed a child SA)"
            else:
                st.detail = "IPsec SA established but the tunnel carried no traffic"
            st.log = sec_log + "\n\n" + _server_ipsec_state()
        else:
            st.status = Status.PASS
            st.detail = "bare GRE dropped, ESP-transport GRE carried traffic"
            st.log = sec_log
    except Exception as e:  # noqa: BLE001
        st.status = Status.ERROR
        st.detail = str(e)[:200]
    out.append(st)

    # ---- FOU (UDP encapsulation) ---------------------------------------
    st2 = SubTest("gre-fou-mode")
    try:
        _set(ipsecEnable=False, allowRaw=True, fouEnable=True)
        gre_mod.disconnect(cA)
        fou_ok, _, fou_log = gre_mod.connect(cA, ib, "A", server_ip=sc.server_ip, mode="fou")
        gre_mod.disconnect(cA)
        st2.status = Status.PASS if fou_ok else Status.FAIL
        st2.detail = ("GRE over UDP carried traffic" if fou_ok
                      else "FOU-encapsulated GRE passed no traffic")
        st2.log = fou_log
    except Exception as e:  # noqa: BLE001
        st2.status = Status.ERROR
        st2.detail = str(e)[:200]
    out.append(st2)

    # ---- restore raw mode for the rest of the suite ---------------------
    try:
        _set(ipsecEnable=False, allowRaw=True, fouEnable=False)
    except Exception as e:  # noqa: BLE001
        log(f"-> WARNING: could not restore GRE raw mode: {str(e)[:150]}")
    return out


def _wgc_psk_check(spare, sc, panel, log, proto="wg-c") -> SubTest:
    """Prove WireGuard/AmneziaWG preshared-key mode end-to-end: build a psk-enabled
    wgc/awg inbound (single account), require a real handshake + internet through it,
    then delete it. The primary suite ran the no-PSK path, so together they cover both
    modes. `proto` selects wg-c (kernel wireguard, wgc_mod) or awg (amneziawg, awg_mod)
    so awg's psk-mode subtest exercises awg itself, not wg-c under the awg column."""
    is_awg = proto == "awg"
    mod = awg_mod if is_awg else wgc_mod
    _fetch = server_setup._fetch_awg_configs if is_awg else server_setup._fetch_wg_configs
    # Distinct from the primary (51821/51820) and second (51823/51821) ports of each
    # protocol so a psk inbound can never collide with them; awg uses its own port.
    psk_port = 51824 if is_awg else 51822
    remark = "test-awg-psk" if is_awg else "test-wgc-psk"
    st = SubTest("psk-mode")
    log(f"-> psk-mode (preshared-key {proto} inbound: handshake + internet)...")
    acct = server_setup._acct("awgpsk" if is_awg else "wgpsk", 0)
    settings = {
        "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
        "pskEnable": True,
        "clientToClient": True, "crossInbound": True,
        "clients": [server_setup._dict_client(acct)],
    }
    second = None
    try:
        inb = panel.add_inbound(remark, psk_port, proto, settings)
        second = server_setup.Inbound(
            protocol=proto, inbound_id=inb["id"], udp_port=psk_port, tcp_port=0,
            accounts={"A": acct}, user_limit=1)
        _fetch(panel, second)
        time.sleep(4)   # peer add + interface up
        spare.disconnect_all()
        time.sleep(2)
        ok, ip, clog = mod.connect(spare, second, "A", server_ip=sc.server_ip)
        net = checks.internet(spare) if ok else None
        works = bool(ok and net and net.status == Status.PASS)
        cfg0 = (second.wg_configs.get("A") or [{}])[0]
        has_psk = "PresharedKey" in (cfg0.get("config") or "")
        st.log = (f"psk_in_config={has_psk} connect_ok={ok} ip={ip!r} "
                  f"net={net.status.value if net else 'n/a'}\n{clog[-500:]}")
        if works and has_psk:
            st.status = Status.PASS
            st.detail = f"preshared-key tunnel established ({ip}) with internet"
        elif not has_psk:
            st.status = Status.FAIL
            st.detail = "psk mode enabled but the rendered client config has no PresharedKey line"
        else:
            st.status = Status.FAIL
            st.detail = (f"psk tunnel did not pass traffic "
                         f"(ok={ok} net={net.status.value if net else 'n/a'})")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    finally:
        mod.disconnect(spare)
        spare.disconnect_all()
        if second is not None:
            try:
                panel.del_inbound(second.inbound_id)
                time.sleep(3)
            except Exception:  # noqa: BLE001
                pass
    return st


def _ovpn_status_rows(server_exec, inbound_id, transport):
    """Parse the server's OpenVPN status-v3 file into CLIENT_LIST rows (each a list
    of tab fields: [0]CLIENT_LIST [3]VirtualAddr [10]ClientID). [] if unreadable."""
    if server_exec is None:
        return []
    try:
        _, out, _ = server_exec(
            f"cat /var/run/openvpn/status-{inbound_id}-{transport}.log 2>/dev/null")
    except Exception:  # noqa: BLE001
        return []
    return [ln.split("\t") for ln in out.split("\n") if ln.startswith("CLIENT_LIST\t")]


def _ovpn_cid_at_ip(rows, ip) -> str:
    """Client-ID of the session holding virtual address `ip` ("" if none)."""
    for f in rows:
        if len(f) > 10 and f[3] == ip:
            return f[10].strip()
    return ""


def _ovpn_cid_present(rows, cid) -> bool:
    """True if any session has client-ID `cid` (False for cid="")."""
    return bool(cid) and any(len(f) > 10 and f[10].strip() == cid for f in rows)


def _iface_up(client: Client, proto: str) -> bool:
    iface = "tun0" if proto in ("openvpn", "openconnect") else "ppp0"
    return bool(client.wait_iface(iface, timeout=3))


def _multi_inbound_check(proto, cA, cB, cC, sc, panel, log) -> SubTest:
    """TEST 1: prove the panel supports MULTIPLE inbounds of the SAME protocol at
    once. Create a SECOND inbound of `proto` (distinct port + IP pool + its own
    account), connect a spare client to it and reach the internet, then prove the
    FIRST (setup) inbound STILL works — distinct tunnel IP, no port/pool clash. The
    2nd inbound is DELETED at the end so it can't pollute later phases.

    For l2tp/pptp the daemon binds one fixed port (1701/1723) for every inbound, so
    the 2nd inbound is reached by connecting with ITS account (RADIUS lands it in
    the 2nd inbound's distinct /24 pool); only openvpn listens on its own per-inbound
    port. Either way the proof is: both inbounds online, on distinct pools."""
    st = SubTest("multi-inbound-same-proto")
    log(f"-> multi-inbound-same-proto (2nd {proto} inbound, new port/pool)...")
    spare = cC          # cA/cB drive the shared suite; cC is free at this point
    variant = _SECOND_VARIANT.get(proto)
    second = None
    try:
        try:
            second = server_setup.build_second_inbound(panel, proto)
        except Exception as e:  # noqa: BLE001
            # The panel refusing a 2nd same-proto inbound is the very regression
            # this test guards -> FAIL (not SKIP), carrying the panel error.
            st.status = Status.FAIL
            st.detail = f"could not create a 2nd {proto} inbound: {str(e)[:120]}"
            st.log = str(e)[:500]
            return st
        time.sleep(6)   # new-inbound save -> config regen + daemon restart

        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)
        # (a) connect the spare client to the 2nd inbound's OWN account
        ok2, ip2, log2 = _connect(spare, sc, proto, "A", variant, ib=second)
        net2 = checks.internet(spare) if (ok2 and ip2) else None
        second_ok = bool(ok2 and ip2 and net2 and net2.status == Status.PASS)
        _disconnect(spare, proto)
        spare.disconnect_all()
        time.sleep(2)
        # (b) prove the FIRST (setup) inbound still works (dial its account A)
        ok1, ip1, log1 = _connect(spare, sc, proto, "A", variant)   # primary
        net1 = checks.internet(spare) if (ok1 and ip1) else None
        first_ok = bool(ok1 and ip1 and net1 and net1.status == Status.PASS)
        _disconnect(spare, proto)
        spare.disconnect_all()
        time.sleep(2)

        p1, p2 = sc.inbounds[proto].udp_port, second.udp_port
        if proto == "ssh" or proto in XRAY_NATIVE:
            # Relays and Xray-native proxies: no tunnel IP and no /24 pool to compare.
            # The two inbounds bind DISTINCT ports and each serves its own account; the
            # proof is that the spare reached the internet through BOTH (2nd inbound's
            # account, then the 1st inbound's account A), i.e. the two coexist.
            # For anytls/tuic/naive that is a sharper claim than for ssh: both listeners
            # live in the SAME xray process, rendered into ONE config by the panel, so a
            # duplicate tag or a settings block overwriting its sibling takes the whole
            # core down rather than just the second inbound.
            distinct = p1 != p2
            distinct_desc = f"distinct listener ports ({p1} vs {p2}): {distinct}"
            pool_word = "ports"
        else:
            # distinct tunnel IP AND distinct /24 pool (different inbounds own different
            # /24s, so the third octet differs) -> proves separate pools, no clash.
            distinct = bool(ip1 and ip2 and ip1 != ip2
                            and ip1.split(".")[2] != ip2.split(".")[2])
            distinct_desc = f"distinct tunnel IP + distinct /24 pool: {distinct}"
            pool_word = "pools"
        st.log = (f"2nd inbound id={second.inbound_id} port={p2} variant={variant}: "
                  f"conn={ok2} ip={ip2!r} net={net2.status.value if net2 else 'n/a'}\n"
                  f"1st inbound id={sc.inbounds[proto].inbound_id} port={p1}: "
                  f"conn={ok1} ip={ip1!r} net={net1.status.value if net1 else 'n/a'}\n"
                  f"{distinct_desc}\n"
                  f"-- 2nd connect --\n{log2[-350:]}\n-- 1st connect --\n{log1[-350:]}")
        if second_ok and first_ok and distinct:
            st.status = Status.PASS
            st.detail = (f"two {proto} inbounds coexist: 2nd(:{p2},{ip2}) + "
                         f"1st(:{p1},{ip1}) both online on distinct {pool_word}")
        elif not second_ok:
            st.status = Status.FAIL
            st.detail = (f"2nd {proto} inbound not usable "
                         f"(conn={ok2} ip={ip2!r} net={net2.status.value if net2 else 'n/a'})")
        elif not first_ok:
            st.status = Status.FAIL
            st.detail = (f"1st {proto} inbound broke after adding a 2nd "
                         f"(conn={ok1} ip={ip1!r} net={net1.status.value if net1 else 'n/a'})")
        else:
            st.status = Status.FAIL
            st.detail = f"both online but tunnel IPs/pools not distinct (ip1={ip1} ip2={ip2})"
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    finally:
        # clean up the 2nd inbound so it can't pollute later phases (bulk-ops etc.)
        if second is not None:
            try:
                panel.del_inbound(second.inbound_id)
                time.sleep(4)
            except Exception as e:  # noqa: BLE001
                st.log += f"\n(cleanup: del 2nd inbound failed: {e})"
    return st


def _ipsec_not_stuck(ib, panel, server_exec, log) -> SubTest:
    """TEST 2 (l2tp only): L2TP/IPsec uses libreswan; a known regression is IPsec
    "stuck on Stopped" from version-dependent config keywords (GenerateIPsecConfig
    version-gates against exactly this). Assert IPsec is NOT stuck stopped when it's
    expected up (l2tp/ipsec configured AND libreswan present). NA when not applicable
    (inbound has no PSK, or libreswan unavailable on the host, e.g. Arch). FAIL only
    when it was expected up but the service is inactive.

    Two corroborating signals: the panel's dedicated `ipsec` core status
    (state=running = ipsec.service active; state!=not_installed = `ipsec` CLI
    present) and a server-side probe (`systemctl is-active ipsec`, `ipsec
    status/whack`). OR'd toward PASS so a FAIL means BOTH views agree IPsec is
    down."""
    st = SubTest("ipsec-not-stuck")
    log("-> ipsec-not-stuck (l2tp/ipsec must not be stuck Stopped)...")
    try:
        # IPsec is now its OWN core in /panel/core/status (was buried in the l2tp
        # core's extra={ipsec,libreswan}). state=="running" -> ipsec.service active;
        # state!="not_installed" -> libreswan (`ipsec` CLI) present on the host.
        core = panel.core("ipsec") if panel is not None else {}
        state = core.get("state", "?")
        p_ipsec = state == "running"
        p_libreswan = state not in ("", "?", "not_installed")
        # server-side corroboration (POSIX sh; printf avoids `echo -n` quirks).
        sdump = ""
        if server_exec is not None:
            try:
                _, sdump, _ = server_exec(
                    "printf 'is-active=%s\\n' \"$(systemctl is-active ipsec 2>/dev/null)\"; "
                    "printf 'have=%s\\n' \"$(command -v ipsec >/dev/null 2>&1 && echo yes || echo no)\"; "
                    "echo '--- ipsec status ---'; ipsec status 2>/dev/null | tail -n 15; "
                    "echo '--- whack ---'; ipsec whack --status 2>/dev/null | tail -n 15")
            except Exception as e:  # noqa: BLE001
                sdump = f"(server ipsec query failed: {e})"
        s_active = "is-active=active" in sdump
        s_have = "have=yes" in sdump
        libreswan_avail = p_libreswan or s_have
        ipsec_up = p_ipsec or s_active
        st.log = (f"panel ipsec core: state={state} (running={p_ipsec} "
                  f"libreswan_present={p_libreswan})\n"
                  f"server: is-active(active)={s_active} have-ipsec={s_have}\n{sdump[:1200]}")
        if not getattr(ib, "psk", ""):
            st.status = Status.NA
            st.detail = "l2tp inbound has no IPsec PSK (ipsec not requested) — not applicable"
        elif not libreswan_avail:
            st.status = Status.NA
            st.detail = "libreswan/IPsec unavailable on this host (e.g. Arch) — L2TP/IPsec not applicable"
        elif ipsec_up:
            st.status = Status.PASS
            st.detail = (f"IPsec service active (not stuck stopped): "
                         f"panel.ipsec={p_ipsec} server.active={s_active}")
        else:
            st.status = Status.FAIL
            st.detail = ("IPsec STUCK stopped: libreswan present + l2tp/ipsec configured, "
                         f"but ipsec service inactive (panel.ipsec={p_ipsec} "
                         f"server.active={s_active}, l2tp state={state})")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    return st
