"""multi-inbound: ONE account, every protocol the panel serves, one bill.

The accounts layer (`clients` + `account_inbounds`) turned "the same person on N
inbounds" from N separate accounts with N emails, N quotas and N expiries into one
account with one of each, projected onto every member inbound's `settings.clients`.
Everything downstream of that projection is unchanged code being fed a shape it never
saw before, and this phase is the only place that drives it end to end.

It creates ONE account, puts it on an inbound of EVERY account-bearing protocol, and
then asserts the six things an operator is actually selling:

  1. connectivity   - the projected credential works on every member inbound. This is
                      the projection's real test: each protocol keys on a DIFFERENT
                      field (uuid / vpn_username+password / password / secret), all
                      minted by ensureCredentialsFor when the account joined.
  2. traffic count  - bytes pulled through ANY member inbound land on the ONE
                      client_traffics row for the account's email, and nowhere else.
  3. multiplier     - a per-INBOUND weight bills at the rate of the inbound the
                      traffic came from, even though there is one account behind all
                      of them. Set on one member, the others must stay 1:1.
  4. traffic limit  - one totalGB for the whole account. Exceeding it through ONE
                      protocol must disable the account, not just that membership.
  5. ip limit       - one limitIp for the whole account, counted as a UNION across
                      inbounds (speedlimit.go merges per email, minimum non-zero).
  6. suspension     - enable=false reaches every member inbound; re-enabling restores
                      all of them.

Protocol coverage is the whole point, so it is deliberately wider than any other
phase: the nine bundled-daemon VPNs, the two relays, and the seven Xray-native
protocols including the four classic ones (vmess/vless/trojan/shadowsocks) that
nothing in this harness had ever dialled before (clients/xrayclassic.py).

Which inbounds it uses: the ones server-setup already built, plus four it builds
itself for the classic Xray protocols. Those four are kept in `sc.multi_inbounds`
rather than `sc.inbounds` on purpose - bulk-ops, backup, subscription and the routing
assert all iterate `sc.inbounds`, and silently widening that set would change phases
that have nothing to do with this one.
"""
from __future__ import annotations

import json
import time
import uuid

from . import abort
from . import protocols
from . import server_setup
from . import traffic
from .clients import mtproto as mt_mod
from .clients import xrayclassic
from .model import SubTest, Status, PHASE_MULTI
from .server_setup import Account, Inbound

MB = 1024 * 1024

# The account under test. One email, one row, one quota - whatever it is dialled over.
EMAIL = "multi@t"
SUBID = "multiacct"

# Ports for the four classic Xray inbounds this phase adds. Above every port
# server_setup uses (its highest is the 8457-8459 second-inbound block) so nothing
# collides, and contiguous so a firewall note about them is one range.
CLASSIC_PORTS = {"vmess": 8461, "vless": 8462, "trojan": 8463, "shadowsocks": 8464}
HYSTERIA_PORT = 8465

# Dial variant per protocol, mirroring protocols._variants' PRIMARY choice. l2tp is
# resolved at runtime (raw when ikev2 owns 500/4500), see _l2tp_variant.
VARIANT = {"openvpn": ("udp", "new"), "openconnect": "dtls"}

# Enforcement family, reported alongside every result. These are genuinely different
# code paths reaching the same account flag, and a green result on one says nothing
# about the others:
#   radius - the in-binary RADIUS server checks quota/enable at AUTH time, so a
#            disabled account is refused on the next dial and an already-connected
#            session is cut by the disconnect sweep.
#   sweep  - no auth event exists at all (a WireGuard peer is installed, not logged
#            in), so enforcement is the rbridge sweep removing the peer.
#   relay  - the relay process (telemt / the in-binary SSH gateway) admits per
#            connection from its own copy of the account.
#   xray   - the core's own inbound user list plus the speedlimit sidecar.
FAMILY = {
    "openvpn": "radius", "l2tp": "radius", "pptp": "radius",
    "openconnect": "radius", "sstp": "radius", "ikev2": "radius",
    "wg-c": "sweep", "awg": "sweep", "gre": "sweep",
    "ssh": "relay", "mtproto": "relay",
    "vmess": "xray", "vless": "xray", "trojan": "xray", "shadowsocks": "xray",
    "anytls": "xray", "tuic": "xray", "naive": "xray",
}

# Dial order. Cheap and reliable first so a rig problem surfaces early, and the two
# IKE-adjacent ones (l2tp, ikev2) next to each other so their shared 500/4500 story is
# read in one place in the log.
ORDER = ["vless", "vmess", "trojan", "shadowsocks", "anytls", "tuic", "naive",
         "ssh", "mtproto",
         "openvpn", "l2tp", "pptp", "openconnect", "sstp", "ikev2",
         "wg-c", "awg", "gre"]

# Protocols with no tunnel and no proxy: connectivity is proven by a protocol probe
# rather than by routing the VM's traffic. mtproto is a RELAY to Telegram, so "is the
# internet reachable" is not a question it can answer.
PROBE_ONLY = ("mtproto",)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _online(client, tries: int = 3, gap: int = 3) -> tuple[bool, str]:
    """Is the internet reachable from this VM right now?

    Deliberately NOT checks.internet: that one retries for ~100s, which is right when
    a pass is expected and wrong for the disabled-account sweeps, where every protocol
    is expected to FAIL and the retries would add half an hour to the phase. Same
    request, caller-chosen patience."""
    code = ""
    for i in range(tries):
        _, code = client.sh(
            "curl -s -o /dev/null -w '%{http_code}' --max-time 10 "
            "https://www.google.com/generate_204")
        if code.strip() in ("200", "204"):
            return True, f"HTTP {code.strip()} (attempt {i + 1})"
        if i + 1 < tries:
            time.sleep(gap)
    return False, f"no internet (last http_code={code.strip()!r})"


def _l2tp_variant(panel, ib) -> str:
    """"ipsec" only when the inbound really has IPsec on. server_setup turns it off
    whenever ikev2 is in the run (one IKE daemon can own 500/4500), and it sets
    Inbound.psk either way, so the flag has to be read off the panel."""
    try:
        settings = json.loads(panel.get_inbound(ib.inbound_id).get("settings") or "{}")
        return "ipsec" if settings.get("ipsecEnable") else "raw"
    except Exception:  # noqa: BLE001
        return "raw"


def _inbound_of(sc, proto: str) -> Inbound | None:
    if proto in xrayclassic.SPECS:
        return (getattr(sc, "multi_inbounds", None) or {}).get(proto)
    return sc.inbounds.get(proto)


def _dial(client, sc, panel, proto: str):
    """Bring the account up over `proto`. Returns (ok, tunnel_ip, log)."""
    ib = _inbound_of(sc, proto)
    if ib is None:
        return False, "", f"no {proto} inbound was built"
    if proto in xrayclassic.SPECS:
        return xrayclassic.connect(client, ib, "M", server_ip=sc.server_ip)
    variant = VARIANT.get(proto)
    if proto == "l2tp":
        variant = _l2tp_variant(panel, ib)
    return protocols._connect(client, sc, proto, "M", variant=variant, ib=ib)


def _hangup(client, proto: str):
    try:
        if proto in xrayclassic.SPECS:
            xrayclassic.disconnect(client, proto)
        elif proto in PROBE_ONLY:
            mt_mod.disconnect(client)
        else:
            protocols._disconnect(client, proto)
    except Exception:  # noqa: BLE001
        pass


def _probe_mtproto(client, sc, proto_ib, mode: str = "classic"):
    """mtproto connectivity: an obfuscated2 handshake through the proxy that must
    reach a real Telegram DC. Returns (ok, detail, log)."""
    verdict, info, log = mt_mod.probe(client, proto_ib, "M", mode, sc.server_ip)
    return verdict, str(info)[:200], log


def _counted(panel, email: str) -> int:
    return traffic._counted(panel, email)[0]


def _settle(panel, email: str, base: int, want: int, timeout: int = 90) -> tuple[int, list]:
    """Poll the account's counter until it clearly reflects `want` more bytes, or it
    stops growing for two whole accounting cycles (the job folds every 10s)."""
    delta, last_grow, traj = 0, time.monotonic(), []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        d = _counted(panel, email) - base
        traj.append(d)
        if d > delta:
            delta, last_grow = d, time.monotonic()
        if want and delta >= want:
            break
        if delta > 0 and time.monotonic() - last_grow >= 22:
            break
        time.sleep(8)
    return delta, traj


# ---------------------------------------------------------------------------
# stage 1: the four classic Xray inbounds
# ---------------------------------------------------------------------------
def _build_classic(panel, sc, phase, log) -> None:
    """vmess / vless / trojan / shadowsocks, created with NO clients.

    Empty on purpose. The ONLY account on them is the multi-inbound one, added later
    by membership, which makes them the clean case: an account joining an inbound that
    has never held a client entry, where every credential the protocol needs has to be
    minted by the accounts layer rather than copied off a neighbour."""
    sc.multi_inbounds = {}
    ss_pw = uuid.uuid4().hex

    for proto, settings, stream in (
        ("vless", {"clients": [], "decryption": "none", "fallbacks": []},
         {"network": "tcp", "security": "none"}),
        ("vmess", {"clients": []},
         {"network": "tcp", "security": "none"}),
        # trojan without TLS is not trojan: the server tells a valid password from a
        # probe by falling back to a decoy, and the whole exchange is defined inside
        # the TLS stream. Reuses the self-signed cert helper the other TLS inbounds use.
        ("trojan", {"clients": [], "fallbacks": []},
         server_setup._xray_stream(panel, "tcp")),
        # aes-256-gcm: AEAD, so the inbound is single-port multi-user, and NOT a 2022
        # method, so an ordinary string password is legal. See ss2022_credential_check.
        ("shadowsocks", {"clients": [], "method": xrayclassic.SS_METHOD,
                         "password": ss_pw, "network": "tcp,udp"},
         {"network": "tcp", "security": "none"}),
    ):
        st = phase.add(SubTest(f"inbound-{proto}"))
        port = CLASSIC_PORTS[proto]
        try:
            inb = panel.add_inbound(f"test-{proto}", port, proto, settings, stream=stream)
            iid = inb.get("id")
            if not iid:
                raise RuntimeError(f"panel returned no inbound id: {inb}")
            sc.multi_inbounds[proto] = Inbound(
                protocol=proto, inbound_id=iid, udp_port=port, tcp_port=0,
                accounts={}, user_limit=1,
                tls_sha256=server_setup.stream_cert_sha256(stream))
            st.status = Status.PASS
            st.detail = f"inbound {iid}, port {port}, no clients (the account joins by membership)"
        except Exception as e:  # noqa: BLE001
            st.status, st.detail = Status.ERROR, str(e)[:300]
        log(f"-> inbound-{proto} [{st.status.value}] {st.detail}")


# ---------------------------------------------------------------------------
# stage 2: one account, every inbound
# ---------------------------------------------------------------------------
def _member_ids(sc) -> list:
    """Every inbound the account should be served on, in ORDER-first order.

    sc.ikev2_extra is excluded: ValidateMembershipSet refuses two memberships of the
    same protocol for l2tp/pptp/ikev2 (one shared daemon per protocol, bare
    NAS-Identifier, so the lower id would silently always win), and the primary ikev2
    inbound is already in the set."""
    ids = []
    for proto in ORDER:
        ib = _inbound_of(sc, proto)
        if ib is not None:
            ids.append(ib.inbound_id)
    return ids


def _create_account(panel, sc, phase, log) -> tuple[bool, list]:
    """Create the account through ONE addClient carrying the whole membership set.

    The anchor is the VLESS inbound deliberately: an account created through a vless
    anchor was once born with no credentials at all for the other protocols
    (eb803db5), so anchoring here keeps that regression under test."""
    ids = _member_ids(sc)
    st = phase.add(SubTest("account-create"))
    anchor = _inbound_of(sc, "vless")
    if anchor is None or not ids:
        st.status, st.detail = Status.ERROR, "no vless anchor / no inbounds to join"
        log(f"-> account-create [{st.status.value}] {st.detail}")
        return False, ids
    entry = {
        # The anchor is vless, so `id` is read as the account UUID. Every OTHER
        # credential the member protocols key on is left out on purpose: minting them
        # is ensureCredentialsFor's job, and supplying them here would test the
        # harness rather than the panel.
        "id": str(uuid.uuid4()),
        "email": EMAIL, "enable": True, "subId": SUBID,
        "totalGB": 0, "expiryTime": 0, "limitIp": 0,
        "tgId": "", "comment": "multi-inbound E2E", "reset": 0,
    }
    try:
        body = panel.add_client(anchor.inbound_id, entry, inbound_ids=ids)
        st.status = Status.PASS
        st.detail = f"account {EMAIL} created on {len(ids)} inbounds via a vless anchor"
        st.log = f"inboundIds={ids}\nreply={str(body)[:400]}"
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.FAIL, str(e)[:300]
    log(f"-> account-create [{st.status.value}] {st.detail}")
    return st.status == Status.PASS, ids


def _verify_memberships(panel, sc, phase, ids, log) -> None:
    """The accounts layer must show ONE account holding exactly those memberships."""
    st = phase.add(SubTest("account-is-one-row"))
    try:
        listing = panel.list_accounts(search=EMAIL)
        rows = listing if isinstance(listing, list) else (listing.get("rows")
                                                          or listing.get("clients")
                                                          or listing.get("items") or [])
        mine = [r for r in rows if (r.get("email") or "").lower() == EMAIL]
        if len(mine) != 1:
            st.status = Status.FAIL
            st.detail = f"expected exactly 1 account row for {EMAIL}, got {len(mine)}"
            st.log = json.dumps(rows)[:1500]
        else:
            row = mine[0]
            got = (row.get("memberships") or row.get("inboundIds")
                   or row.get("inbounds") or [])
            if isinstance(got, list) and got and isinstance(got[0], dict):
                got = [g.get("inboundId") or g.get("id") for g in got]
            missing = sorted(set(ids) - set(got or []))
            st.status = Status.PASS if not missing else Status.FAIL
            st.detail = (f"one account, {len(got or [])} memberships"
                         if not missing else
                         f"account is missing memberships {missing}")
            st.log = json.dumps(row)[:1500]
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:250]
    log(f"-> account-is-one-row [{st.status.value}] {st.detail}")


def _adopt_credentials(panel, sc, phase, log) -> list:
    """Read the projected client entry back off every member inbound and turn it into
    the harness Account the client drivers dial with.

    This is the crux of the phase. Nothing here CHOOSES a credential: whatever the
    projection wrote is what gets dialled, so a blank password or a uuid written into
    the wrong field shows up as a dead protocol rather than as a harness that quietly
    used the value it wanted. Returns the protocols that are dialable."""
    ready = []
    for proto in ORDER:
        ib = _inbound_of(sc, proto)
        if ib is None:
            continue
        st = phase.add(SubTest(f"credentials-{proto}"))
        try:
            entry = panel.get_client(ib.inbound_id, EMAIL)
            if not entry:
                st.status = Status.FAIL
                st.detail = "the account was not projected onto this inbound at all"
                log(f"-> credentials-{proto} [fail] {st.detail}")
                continue
            slot = entry.get("slot")
            acct = Account(
                user=str(entry.get("id") or ""),
                password=str(entry.get("password") or ""),
                email=EMAIL,
                index=int(slot) if isinstance(slot, int) else _list_index(panel, ib),
                uuid=str(entry.get("id") or ""),
                security=str(entry.get("security") or ""),
                secret=str(entry.get("secret") or ""),
            )
            ib.accounts["M"] = acct
            missing = _missing_credential(proto, entry)
            st.log = json.dumps(entry)[:1200]
            if missing:
                st.status = Status.FAIL
                st.detail = f"projection left {missing} empty, the account cannot authenticate"
            else:
                st.status = Status.PASS
                st.detail = (f"slot={acct.index} "
                             f"id={_ellipsis(acct.user)} pw={_ellipsis(acct.password)}"
                             + (f" secret={_ellipsis(acct.secret)}" if acct.secret else ""))
                ready.append(proto)
        except Exception as e:  # noqa: BLE001
            st.status, st.detail = Status.ERROR, str(e)[:250]
        log(f"-> credentials-{proto} [{st.status.value}] {st.detail}")

    # Per-protocol material the panel MINTS rather than stores in the entry: the
    # wg-c/awg per-device keypairs, the GRE peer addresses, and the mtproto secret in
    # its three client-facing shapes. Fetched exactly as server_setup does for its own
    # accounts, so the client drivers read them from the usual place.
    for proto, fetch in (("wg-c", server_setup._fetch_wg_configs),
                         ("awg", server_setup._fetch_awg_configs),
                         ("gre", server_setup._fetch_gre_configs)):
        ib = _inbound_of(sc, proto)
        if ib is not None and "M" in ib.accounts:
            try:
                fetch(panel, ib)
            except Exception:  # noqa: BLE001
                pass
    ib = _inbound_of(sc, "mtproto")
    if ib is not None and "M" in ib.accounts:
        ib.mt_secrets = dict(ib.mt_secrets or {})
        ib.mt_secrets["M"] = server_setup._mt_secret_shapes(ib.accounts["M"].secret)
    return ready


def _list_index(panel, ib) -> int:
    """Position of the account in the inbound's clients array, the fallback the panel
    itself uses when a membership predates slots."""
    try:
        settings = json.loads(panel.get_inbound(ib.inbound_id).get("settings") or "{}")
        for i, c in enumerate(settings.get("clients", [])):
            if (c.get("email") or "") == EMAIL:
                return i
    except Exception:  # noqa: BLE001
        pass
    return 0


def _missing_credential(proto: str, entry: dict) -> str:
    """Which credential field this protocol needs and did not get. Mirrors
    accountproject.go::applyAccountCredential, from the other side."""
    def blank(k):
        return not str(entry.get(k) or "").strip()
    if proto in ("vmess", "vless"):
        return "id (uuid)" if blank("id") else ""
    if proto in ("trojan", "shadowsocks", "anytls", "naive"):
        return "password" if blank("password") else ""
    if proto == "tuic":
        return "id (uuid)" if blank("id") else ("password" if blank("password") else "")
    if proto in ("l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "ssh"):
        if blank("id"):
            return "id (vpn username)"
        return "password" if blank("password") else ""
    if proto == "mtproto":
        return "secret" if blank("secret") else ""
    return ""   # wg-c / awg / gre: identity is the email, keys are minted elsewhere


def _ellipsis(s: str, n: int = 10) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "…"


def _check_mtproto_membership(panel, sc, phase, log) -> None:
    """A fresh mtproto membership needs exactly one thing of its own: the SECRET.

    The account layer does not model per-protocol fields (renderClientEntry overlays
    what the account owns onto whatever the entry already was, and a brand new
    membership has no entry to overlay onto), so anything a membership cannot inherit
    has to be minted for it. The connection modes used to be in that category, and a
    membership arriving with all three off was an account that existed, looked fine
    and could not connect in any transport. They belong to the INBOUND now, which the
    membership joins already configured; the secret is what is left."""
    ib = _inbound_of(sc, "mtproto")
    if ib is None or "M" not in ib.accounts:
        return
    st = phase.add(SubTest("mtproto-membership-secret"))
    try:
        entry = panel.get_client(ib.inbound_id, EMAIL)
        st.log = json.dumps(entry)[:800]
        secret = (entry.get("secret") or "").strip()
        if secret:
            st.status = Status.PASS
            st.detail = f"the new membership was minted a secret ({len(secret)} chars)"
        else:
            st.status = Status.FAIL
            st.detail = ("a new mtproto membership arrived with NO secret: the account "
                         "is dropped from the proxy config and cannot connect")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:250]
    log(f"-> mtproto-membership-secret [{st.status.value}] {st.detail}")


# ---------------------------------------------------------------------------
# stage 3: connectivity + accounting, one pass over every protocol
# ---------------------------------------------------------------------------
def _sweep_connect_and_count(cA, sc, panel, cfg, phase, ready, log) -> dict:
    """Dial each protocol as the ONE account, prove it works, and prove the bytes it
    moves land on that account's single counter. Returns {proto: counted_delta}."""
    tp = cfg.get("traffic_test", {}) or {}
    n = int(tp.get("usage_mb", 15)) * MB
    urls = tp.get("urls") or traffic.DEFAULT_URLS
    deltas = {}

    for proto in ORDER:
        if abort.is_set():
            break
        if proto not in ready:
            continue
        ib = _inbound_of(sc, proto)
        fam = FAMILY.get(proto, "?")
        cst = phase.add(SubTest(f"connect-{proto}"))
        ust = phase.add(SubTest(f"usage-{proto}"))
        log(f"-> {proto} ({fam}): dialling as the multi-inbound account…")
        try:
            if proto in PROBE_ONLY:
                _connect_probe_only(cA, sc, panel, ib, proto, cst, ust, urls, deltas, log)
                continue
            ok, tip, clog = _dial(cA, sc, panel, proto)
            if not ok:
                cst.status, cst.detail, cst.log = Status.FAIL, "tunnel did not come up", clog[-2500:]
                ust.status, ust.detail = Status.SKIP, "not connected"
                log(f"-> connect-{proto} [fail] tunnel did not come up")
                continue
            online, why = _online(cA, tries=6, gap=4)
            cst.log = clog[-2500:]
            if not online:
                cst.status = Status.FAIL
                cst.detail = f"tunnel up ({tip}) but {why}"
                ust.status, ust.detail = Status.SKIP, "no internet through the tunnel"
                log(f"-> connect-{proto} [fail] {cst.detail}")
                continue
            cst.status = Status.PASS
            cst.detail = f"{fam}: connected as {EMAIL} ({tip or 'proxy'}), {why}"
            log(f"-> connect-{proto} [pass] {cst.detail}")

            base = _counted(panel, EMAIL)
            size, dlog = traffic._download(cA, n, urls)
            if size < n * 0.5:
                ust.status = Status.NA
                ust.detail = f"could not pull {n // MB}MB through the tunnel (got {size}B)"
                ust.log = dlog
            else:
                delta, traj = _settle(panel, EMAIL, base, int(size * 0.8))
                deltas[proto] = delta
                ust.log = (f"downloaded {size}B, counted delta {delta}B "
                           f"(baseline {base})\ntrajectory {traj}\n{dlog}")
                lo, hi = size * 0.7, size * 1.6
                if lo <= delta <= hi:
                    ust.status = Status.PASS
                    ust.detail = (f"{delta // MB}MB billed to {EMAIL} for {size // MB}MB "
                                  f"pulled over {proto}")
                elif delta <= 0:
                    ust.status = Status.FAIL
                    ust.detail = f"{size}B moved over {proto} and NOTHING was billed to {EMAIL}"
                else:
                    ust.status = Status.FAIL
                    ust.detail = (f"billed {delta}B for {size}B over {proto} "
                                  f"(outside [{int(lo)}, {int(hi)}])")
            log(f"-> usage-{proto} [{ust.status.value}] {ust.detail}")
        except Exception as e:  # noqa: BLE001
            cst.status = cst.status if cst.status != Status.SKIP else Status.ERROR
            ust.status, ust.detail = Status.ERROR, str(e)[:250]
            log(f"-> {proto} [error] {str(e)[:200]}")
        finally:
            _hangup(cA, proto)
    return deltas


def _connect_probe_only(cA, sc, panel, ib, proto, cst, ust, urls, deltas, log):
    """mtproto: a relay, so connectivity is a handshake that reaches a real Telegram
    DC and accounting is the bytes the relay moved, not a download."""
    ok, plog = mt_mod.ensure_probe(cA)
    if not ok:
        cst.status, cst.detail, cst.log = Status.ERROR, "prober not available", plog
        ust.status, ust.detail = Status.SKIP, "prober not available"
        return
    verdict, info, log_txt = _probe_mtproto(cA, sc, ib)
    cst.log = log_txt[-2500:]
    if verdict == "na":
        cst.status = Status.NA
        cst.detail = "Telegram DCs unreachable from this rig"
        ust.status, ust.detail = Status.NA, "relay unreachable"
        log(f"-> connect-{proto} [na] {cst.detail}")
        return
    if verdict != "pass":
        cst.status, cst.detail = Status.FAIL, f"handshake/relay failed: {info}"
        ust.status, ust.detail = Status.SKIP, "not connected"
        log(f"-> connect-{proto} [fail] {cst.detail}")
        return
    cst.status = Status.PASS
    cst.detail = f"relay: obfuscated2 handshake reached a DC as {EMAIL} ({info})"
    log(f"-> connect-{proto} [pass] {cst.detail}")

    base = _counted(panel, EMAIL)
    pushed, dinfo, dl = mt_mod.drive_bytes(cA, ib, "M", "classic", sc.server_ip,
                                           target_bytes=2 * MB)
    delta, traj = _settle(panel, EMAIL, base, 0, timeout=60)
    deltas[proto] = delta
    ust.log = f"pushed {pushed}B ({dinfo})\ntrajectory {traj}\n{dl[-800:]}"
    if pushed <= 0:
        ust.status, ust.detail = Status.ERROR, f"prober pushed no bytes: {dinfo}"
    elif delta > 0:
        ust.status = Status.PASS
        ust.detail = f"{delta}B billed to {EMAIL} for {pushed}B relayed over mtproto"
    else:
        ust.status = Status.FAIL
        ust.detail = f"{pushed}B relayed over mtproto and NOTHING was billed to {EMAIL}"
    log(f"-> usage-{proto} [{ust.status.value}] {ust.detail}")


def _one_counter_check(panel, sc, phase, deltas, log) -> None:
    """The multi-inbound claim itself: every protocol's bytes accumulated on ONE row,
    and no per-inbound shadow row was created for the account."""
    st = phase.add(SubTest("one-counter-for-all-inbounds"))
    try:
        total = _counted(panel, EMAIL)
        summed = sum(deltas.values())
        rows = []
        for proto in ORDER:
            ib = _inbound_of(sc, proto)
            if ib is None:
                continue
            entry = panel.get_client(ib.inbound_id, EMAIL)
            if entry:
                rows.append(f"{proto}:{entry.get('email')}")
        emails = {r.split(":", 1)[1] for r in rows}
        st.log = (f"per-protocol counted deltas: {deltas}\n"
                  f"summed {summed}B; account row total {total}B\n"
                  f"projected entries: {rows}")
        if emails and emails != {EMAIL}:
            st.status = Status.FAIL
            st.detail = f"the account is projected under more than one email: {sorted(emails)}"
        elif not deltas:
            st.status = Status.SKIP
            st.detail = "no protocol produced a counted delta"
        elif total >= summed * 0.9:
            st.status = Status.PASS
            st.detail = (f"{len(deltas)} protocols billed to the single row "
                         f"{EMAIL}: {total // MB}MB total")
        else:
            st.status = Status.FAIL
            st.detail = (f"row total {total}B is less than the {summed}B billed across "
                         f"{len(deltas)} protocols: traffic is not accumulating on one row")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:250]
    log(f"-> one-counter-for-all-inbounds [{st.status.value}] {st.detail}")


# ---------------------------------------------------------------------------
# stage 4: the traffic multiplier is per INBOUND, the account is not
# ---------------------------------------------------------------------------
# Which inbound's weight bills a byte is decided by trafficmultiplier.go's
# billingInbound: the record's STAMPED source inbound if it has one, otherwise the
# MAX multiplier across every inbound the account is a member of. That split is what
# this stage is shaped around, and it is why the control has to be another VPN
# protocol rather than an Xray-native one:
#
#   * the nine pool VPN protocols count per tunnel address, and an address belongs to
#     exactly one inbound, so their records ARE stamped and each bills at its own
#     inbound's rate. Two of them is therefore a real weighted-vs-unweighted contrast.
#   * the Xray-native protocols are counted by the core under the name
#     "user>>><email>>>>traffic>>>uplink", which has no inbound component at all. One
#     number covers vless AND trojan AND anytls together, so there is nothing to
#     attribute it by and the max across memberships is used deliberately: the
#     ambiguity can only over-bill, never hand out free traffic. Asserting 1:1 there
#     would be asserting a bug.
_MULT_VPN = ("openvpn", "wg-c", "openconnect", "awg", "l2tp", "sstp", "pptp",
             "ikev2", "gre")
_MULT_XRAY = ("vless", "vmess", "anytls", "trojan", "shadowsocks", "tuic", "naive")


def _pick(ready, candidates, exclude=()):
    for c in candidates:
        if c in ready and c not in exclude:
            return c
    return None


def _weighted_pull(cA, sc, panel, cfg, proto, log) -> tuple[int, int, str]:
    """Connect over `proto`, pull multiplier_mb, return (downloaded, counted, log)."""
    tp = cfg.get("traffic_test", {}) or {}
    n = int(tp.get("multiplier_mb", 10)) * MB
    urls = tp.get("urls") or traffic.DEFAULT_URLS
    ok, tip, clog = _dial(cA, sc, panel, proto)
    if not ok:
        return 0, 0, "could not connect: " + clog[-1200:]
    try:
        base = _counted(panel, EMAIL)
        size, dlog = traffic._download(cA, n, urls)
        if size <= 0:
            return 0, 0, "no bytes pulled\n" + dlog
        delta, traj = _settle(panel, EMAIL, base, 0, timeout=90)
        return size, delta, f"pulled {size}B, counted {delta}B, trajectory {traj}\n{dlog}"
    finally:
        _hangup(cA, proto)


def _ratio(delta: int, size: int) -> float:
    return delta / max(size, 1)


def _multiplier_check(cA, sc, panel, cfg, phase, ready, log) -> None:
    tp = cfg.get("traffic_test", {}) or {}
    after = int(tp.get("multiplier_after_mb", 2)) * MB
    mult = float(tp.get("multiplier", 10))
    weighted = _pick(ready, _MULT_VPN)
    control = _pick(ready, _MULT_VPN, exclude=(weighted,))
    native = _pick(ready, _MULT_XRAY)

    st_w = phase.add(SubTest("multiplier-weighted-inbound"))
    st_c = phase.add(SubTest("multiplier-other-inbound-unweighted"))
    st_x = phase.add(SubTest("multiplier-unattributable-uses-max"))
    if not weighted:
        for st in (st_w, st_c, st_x):
            st.status, st.detail = Status.SKIP, "no working VPN inbound to weight"
        log("-> multiplier [skip] no working VPN protocol")
        return

    wib = _inbound_of(sc, weighted)
    log(f"-> multiplier: {mult}x on the {weighted} inbound past {after // MB}MB "
        f"(control={control}, unattributable={native})")
    try:
        panel.set_traffic_multiplier(wib.inbound_id, True, after, mult)
        time.sleep(10)

        # 1. the weighted inbound itself.
        size, delta, wlog = _weighted_pull(cA, sc, panel, cfg, weighted, log)
        st_w.log = wlog
        if size <= 0:
            st_w.status, st_w.detail = Status.NA, "could not pull traffic over " + weighted
        else:
            # Expected: the first `after` bytes at 1x, the rest at `mult`. Encapsulation
            # moves the counted total by tens of percent, so the band is generous - it
            # exists to tell "the multiplier fired" from "it did not", and at 10x those
            # two are nowhere near each other.
            want = after + (size - after) * mult
            if want * 0.5 <= delta <= want * 1.6:
                st_w.status = Status.PASS
                st_w.detail = (f"{weighted}: {size // MB}MB pulled billed as "
                               f"{delta // MB}MB (~{_ratio(delta, size):.1f}x)")
            elif delta < size * 2:
                st_w.status = Status.FAIL
                st_w.detail = (f"{weighted}: {size}B billed as {delta}B "
                               f"(~{_ratio(delta, size):.1f}x) - the {mult}x inbound "
                               f"multiplier did not reach this account")
            else:
                st_w.status = Status.FAIL
                st_w.detail = (f"{weighted}: {size}B billed as {delta}B "
                               f"(~{_ratio(delta, size):.1f}x), outside the band for {mult}x")
        log(f"-> multiplier-weighted-inbound [{st_w.status.value}] {st_w.detail}")

        # 2. THE multi-inbound assertion: a second VPN inbound of the SAME account,
        #    with the weight still set on the first. Its records are stamped with their
        #    own inbound, so it must bill 1:1.
        if not control:
            st_c.status = Status.SKIP
            st_c.detail = "only one VPN protocol is working, so there is no unweighted control"
        else:
            size2, delta2, clog = _weighted_pull(cA, sc, panel, cfg, control, log)
            st_c.log = clog
            if size2 <= 0:
                st_c.status, st_c.detail = Status.NA, "could not pull traffic over " + control
            elif delta2 <= size2 * 1.7:
                st_c.status = Status.PASS
                st_c.detail = (f"{control}: {size2 // MB}MB billed as {delta2 // MB}MB "
                               f"(~{_ratio(delta2, size2):.1f}x) while {weighted} is at "
                               f"{mult}x - the weight followed the inbound, not the account")
            else:
                st_c.status = Status.FAIL
                st_c.detail = (f"{control}: {size2}B billed as {delta2}B "
                               f"(~{_ratio(delta2, size2):.1f}x) - the {weighted} inbound's "
                               f"{mult}x weight leaked onto another inbound of the same account")
        log(f"-> multiplier-other-inbound-unweighted [{st_c.status.value}] {st_c.detail}")

        # 3. the documented fallback. An Xray-native pull cannot be attributed to an
        #    inbound, so it must bill at the MAX across the account's memberships -
        #    which now includes the weighted VPN inbound. Billing it 1:1 would be the
        #    free-traffic side of the ambiguity, which the design rules out on purpose.
        if not native:
            st_x.status = Status.SKIP
            st_x.detail = "no working Xray-native protocol"
        else:
            size3, delta3, xlog = _weighted_pull(cA, sc, panel, cfg, native, log)
            st_x.log = xlog
            if size3 <= 0:
                st_x.status, st_x.detail = Status.NA, "could not pull traffic over " + native
            elif delta3 >= size3 * 2:
                st_x.status = Status.PASS
                st_x.detail = (f"{native}: {size3 // MB}MB billed as {delta3 // MB}MB "
                               f"(~{_ratio(delta3, size3):.1f}x) - an unattributable "
                               f"record billed at the max across the account's memberships")
            else:
                st_x.status = Status.FAIL
                st_x.detail = (f"{native}: {size3}B billed as {delta3}B "
                               f"(~{_ratio(delta3, size3):.1f}x) - the core's counter names "
                               f"no inbound, so this had to bill at the account's MAX "
                               f"({mult}x); billing it 1:1 hands out the difference free")
        log(f"-> multiplier-unattributable-uses-max [{st_x.status.value}] {st_x.detail}")
    except Exception as e:  # noqa: BLE001
        for st in (st_w, st_c, st_x):
            if st.status == Status.SKIP:
                st.status, st.detail = Status.ERROR, str(e)[:250]
    finally:
        try:
            panel.set_traffic_multiplier(wib.inbound_id, False, 0, 1)
            time.sleep(6)
        except Exception as e:  # noqa: BLE001
            log(f"   (multiplier cleanup failed: {e})")


# ---------------------------------------------------------------------------
# stage 5: one quota for the whole account
# ---------------------------------------------------------------------------
_LIMIT_PICKS = ("vless", "vmess", "anytls", "trojan", "openvpn", "openconnect")


def _limit_check(cA, sc, panel, cfg, phase, ready, log) -> bool:
    """Exceed the account's total through ONE inbound and require the ACCOUNT to be
    disabled - not the membership it was exceeded on. Returns True if the account
    ended up disabled (stage 6 then sweeps the consequence)."""
    tp = cfg.get("traffic_test", {}) or {}
    limit = int(tp.get("limit_mb", 15)) * MB
    over = int(tp.get("over_mb", 50)) * MB
    settle = int(tp.get("settle_timeout", 40))
    urls = tp.get("urls") or traffic.DEFAULT_URLS
    proto = _pick(ready, _LIMIT_PICKS)

    st_set = phase.add(SubTest("limit-applies-to-every-membership"))
    st_hit = phase.add(SubTest("limit-disables-the-account"))
    if not proto:
        for st in (st_set, st_hit):
            st.status, st.detail = Status.SKIP, "no working protocol to drive the quota with"
        return False

    ib = _inbound_of(sc, proto)
    try:
        panel.reset_client_traffic(ib.inbound_id, EMAIL)
        time.sleep(8)
        panel.update_client(ib.inbound_id, EMAIL, {"totalGB": limit, "enable": True},
                            inbound_ids=_member_ids(sc))
        time.sleep(10)
        # The quota is the ACCOUNT's, so it must show up on every inbound the account
        # is on - set once, visible everywhere. A quota that only landed on the inbound
        # it was posted to is the multi-inbound bug this whole layer exists to prevent.
        wrong = []
        for p in ORDER:
            other = _inbound_of(sc, p)
            if other is None:
                continue
            entry = panel.get_client(other.inbound_id, EMAIL)
            if not entry:
                continue
            if int(entry.get("totalGB") or 0) != limit:
                wrong.append(f"{p}={entry.get('totalGB')}")
        st_set.log = f"set totalGB={limit} through the {proto} inbound"
        if wrong:
            st_set.status = Status.FAIL
            st_set.detail = f"totalGB did not reach every membership: {', '.join(wrong)}"
        else:
            st_set.status = Status.PASS
            st_set.detail = f"totalGB={limit // MB}MB is on every membership of {EMAIL}"
        log(f"-> limit-applies-to-every-membership [{st_set.status.value}] {st_set.detail}")

        log(f"-> limit: pulling {over // MB}MB over {proto} against a {limit // MB}MB account cap…")
        ok, tip, clog = _dial(cA, sc, panel, proto)
        if not ok:
            st_hit.status, st_hit.detail, st_hit.log = Status.SKIP, "could not connect", clog[-1500:]
            return False
        size, dlog = traffic._download(cA, over, urls)
        disabled, row = False, {}
        deadline = time.monotonic() + settle + 90
        while time.monotonic() < deadline:
            row = panel.get_client_traffics(EMAIL) or {}
            if row and not row.get("enable", True):
                disabled = True
                break
            time.sleep(6)
        st_hit.log = (f"pulled {size}B over {proto} against a {limit}B cap\n"
                      f"final traffic row: {json.dumps(row)}\n{dlog[-600:]}")
        if disabled:
            st_hit.status = Status.PASS
            st_hit.detail = (f"account disabled after {int(row.get('up', 0)) + int(row.get('down', 0))}B "
                             f"counted against a {limit // MB}MB cap (driven over {proto})")
        elif size < limit:
            st_hit.status = Status.NA
            st_hit.detail = f"only {size}B could be pulled, below the {limit}B cap"
        else:
            st_hit.status = Status.FAIL
            st_hit.detail = (f"{size}B pulled over a {limit // MB}MB cap and the account is "
                             f"still enabled: the quota did not disable it")
        log(f"-> limit-disables-the-account [{st_hit.status.value}] {st_hit.detail}")
        return disabled
    except Exception as e:  # noqa: BLE001
        for st in (st_set, st_hit):
            if st.status == Status.SKIP:
                st.status, st.detail = Status.ERROR, str(e)[:250]
        return False
    finally:
        _hangup(cA, proto)


# ---------------------------------------------------------------------------
# stage 6: a disabled account is disabled EVERYWHERE
# ---------------------------------------------------------------------------
def _projection_enable_check(panel, sc, phase, name, want: bool, log) -> None:
    """Every membership's projected entry must agree with the account flag."""
    st = phase.add(SubTest(name))
    wrong = []
    try:
        for p in ORDER:
            ib = _inbound_of(sc, p)
            if ib is None:
                continue
            entry = panel.get_client(ib.inbound_id, EMAIL)
            if not entry:
                continue
            if bool(entry.get("enable")) != want:
                wrong.append(f"{p}={entry.get('enable')}")
        st.status = Status.PASS if not wrong else Status.FAIL
        st.detail = (f"every membership reads enable={want}" if not wrong else
                     f"memberships disagree with the account flag: {', '.join(wrong)}")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:250]
    log(f"-> {name} [{st.status.value}] {st.detail}")


def _one_per_family(ready) -> list:
    """One protocol per enforcement family, in ORDER. Used where the point is that a
    change reached each MECHANISM rather than each protocol - the per-protocol sweep
    is paid once, on the operator-suspend case."""
    picked, seen = [], set()
    for proto in ORDER:
        fam = FAMILY.get(proto)
        if proto in ready and fam not in seen:
            seen.add(fam)
            picked.append(proto)
    return picked


def _suspend_sweep(cA, sc, panel, phase, ready, log, tag: str, only=None) -> None:
    """With the account disabled, NO protocol may carry its traffic.

    The shape of the refusal legitimately differs by family and is recorded rather
    than required: the RADIUS-backed VPNs refuse the dial outright, while a proxy
    establishes its session lazily, so its tunnel device still comes up and the
    account fails one step later as "connected to nothing". Both are a pass; what is
    not is reaching the internet."""
    todo = only if only is not None else [p for p in ORDER if p in ready]
    for proto in ORDER:
        if abort.is_set():
            break
        if proto not in todo:
            continue
        st = phase.add(SubTest(f"{tag}-{proto}"))
        fam = FAMILY.get(proto, "?")
        try:
            if proto in PROBE_ONLY:
                ib = _inbound_of(sc, proto)
                verdict, info, plog = mt_mod.probe(cA, ib, "M", "classic", sc.server_ip,
                                                   expect_fail=True)
                st.log = plog[-1500:]
                if verdict == "na":
                    st.status, st.detail = Status.NA, "Telegram DCs unreachable from this rig"
                elif verdict == "pass":
                    st.status, st.detail = Status.PASS, f"{fam}: the relay refused the disabled account"
                else:
                    st.status = Status.FAIL
                    st.detail = f"{fam}: the relay still served the disabled account ({info})"
                log(f"-> {tag}-{proto} [{st.status.value}] {st.detail}")
                continue
            ok, tip, clog = _dial(cA, sc, panel, proto)
            if not ok:
                st.status = Status.PASS
                st.detail = f"{fam}: the dial was refused outright"
                st.log = clog[-1500:]
            else:
                online, why = _online(cA, tries=2, gap=3)
                st.log = clog[-1200:]
                if online:
                    st.status = Status.FAIL
                    st.detail = (f"{fam}: a DISABLED account still reached the internet "
                                 f"over {proto} ({why})")
                else:
                    st.status = Status.PASS
                    st.detail = f"{fam}: tunnel came up but carried nothing ({why})"
            log(f"-> {tag}-{proto} [{st.status.value}] {st.detail}")
        except Exception as e:  # noqa: BLE001
            st.status, st.detail = Status.ERROR, str(e)[:250]
            log(f"-> {tag}-{proto} [error] {str(e)[:150]}")
        finally:
            _hangup(cA, proto)


def _restore_sweep(cA, sc, panel, phase, ready, log) -> None:
    """Re-enabling brings every family back. One protocol per enforcement family
    rather than all of them: the enabled path was already swept protocol by protocol
    in connect-*, so what is under test here is only that the RE-enable reaches each
    of the four mechanisms."""
    for proto in _one_per_family(ready):
        if abort.is_set():
            break
        st = phase.add(SubTest(f"restore-{proto}"))
        try:
            if proto in PROBE_ONLY:
                ib = _inbound_of(sc, proto)
                verdict, info, plog = mt_mod.probe(cA, ib, "M", "classic", sc.server_ip)
                st.log = plog[-1500:]
                st.status = {"pass": Status.PASS, "na": Status.NA}.get(verdict, Status.FAIL)
                st.detail = (f"{FAMILY[proto]}: relay serves the re-enabled account"
                             if verdict == "pass" else f"still refused after re-enable ({info})")
            else:
                ok, tip, clog = _dial(cA, sc, panel, proto)
                online, why = _online(cA, tries=5, gap=4) if ok else (False, "dial refused")
                st.log = clog[-1500:]
                st.status = Status.PASS if online else Status.FAIL
                st.detail = (f"{FAMILY[proto]}: back online after re-enable ({why})"
                             if online else
                             f"{FAMILY[proto]}: still cut off after re-enable ({why})")
            log(f"-> restore-{proto} [{st.status.value}] {st.detail}")
        except Exception as e:  # noqa: BLE001
            st.status, st.detail = Status.ERROR, str(e)[:250]
        finally:
            _hangup(cA, proto)


# ---------------------------------------------------------------------------
# stage 7: one IP limit, counted across the account's inbounds
# ---------------------------------------------------------------------------
SPEEDLIMIT_PATH = "/root/vpn-ui/bin/speedlimits.json"

# Three Xray-native protocols on three DIFFERENT inbounds. The cap is the CORE's to
# enforce only for these (speedlimit.go::ipLimitEnforcedInCore excludes every VPN
# backend, ssh and mtproto by name: the VPNs already cap devices at RADIUS via the
# account slot allocator, and the two relays reach the core over the loopback, so an
# in-core cap there would see one source address for every account at once).
_IPLIMIT_PROTOS = ("vless", "vmess", "trojan", "shadowsocks", "anytls")
_IP_CAP = 2


def _sidecar(server_exec) -> dict:
    if server_exec is None:
        return {}
    try:
        _, out, _ = server_exec(f"cat {SPEEDLIMIT_PATH} 2>/dev/null || echo '{{}}'", timeout=20)
        return json.loads((out or "{}").strip() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def _ip_limit_check(cA, cB, cC, sc, panel, phase, ready, server_exec, log) -> None:
    picks = [p for p in _IPLIMIT_PROTOS if p in ready][:3]
    st_pub = phase.add(SubTest("ip-limit-published-once-per-account"))
    st_live = phase.add(SubTest("ip-limit-counts-across-inbounds"))
    st_vpn = phase.add(SubTest("ip-limit-not-published-for-vpn-protocols"))

    anchor = _inbound_of(sc, picks[0]) if picks else None
    if anchor is None:
        for st in (st_pub, st_live, st_vpn):
            st.status, st.detail = Status.SKIP, "no working Xray-native protocol to cap"
        return
    try:
        panel.update_client(anchor.inbound_id, EMAIL, {"limitIp": _IP_CAP},
                            inbound_ids=_member_ids(sc))
        time.sleep(12)

        doc = _sidecar(server_exec)
        users = doc.get("users") or doc.get("clients") or []
        mine = [u for u in users if (u.get("email") or "").lower() == EMAIL]
        st_pub.log = json.dumps(doc)[:2000]
        if len(mine) == 1 and int(mine[0].get("ipLimit") or 0) == _IP_CAP:
            st_pub.status = Status.PASS
            st_pub.detail = (f"the sidecar carries ONE entry for {EMAIL} with ipLimit="
                             f"{_IP_CAP}, merged across {len(picks)}+ member inbounds")
        elif len(mine) > 1:
            st_pub.status = Status.FAIL
            st_pub.detail = (f"the sidecar carries {len(mine)} entries for {EMAIL}: the cap "
                             f"is per-inbound, so the account gets {len(mine)}x its limit")
        elif not mine:
            st_pub.status = Status.FAIL
            st_pub.detail = f"limitIp={_IP_CAP} was set but {EMAIL} is absent from the sidecar"
        else:
            st_pub.status = Status.FAIL
            st_pub.detail = f"sidecar ipLimit is {mine[0].get('ipLimit')}, expected {_IP_CAP}"
        log(f"-> ip-limit-published-once-per-account [{st_pub.status.value}] {st_pub.detail}")

        # The VPN/relay half of the same setting: their cap is NOT the core's, and
        # publishing one would refuse real devices (one wg-c account owns a whole CIDR
        # block, and ssh/mtproto reach the core over the loopback).
        st_vpn.log = st_pub.log
        st_vpn.status = Status.PASS
        st_vpn.detail = ("the account appears once, so no per-VPN-inbound cap was published"
                         if len(mine) <= 1 else "extra entries published")
        if len(mine) > 1:
            st_vpn.status = Status.FAIL
        log(f"-> ip-limit-not-published-for-vpn-protocols [{st_vpn.status.value}] {st_vpn.detail}")

        if len(picks) < 3 or cB is None or cC is None:
            st_live.status = Status.SKIP
            st_live.detail = (f"need 3 Xray-native protocols and 3 client VMs "
                              f"(have {len(picks)})")
            return
        # Three DIFFERENT inbounds, three different source addresses, ONE account. Under
        # a per-inbound cap all three would be served; under the account-wide union the
        # third must not be.
        pa, pb, pc = picks[0], picks[1], picks[2]
        log(f"-> ip-limit: {pa}@A + {pb}@B must work, {pc}@C must not (cap {_IP_CAP})")
        oka, _, la = _dial(cA, sc, panel, pa)
        on_a, why_a = _online(cA, tries=5, gap=4) if oka else (False, "dial refused")
        okb, _, lb = _dial(cB, sc, panel, pb)
        on_b, why_b = _online(cB, tries=5, gap=4) if okb else (False, "dial refused")
        okc, _, lc = _dial(cC, sc, panel, pc)
        on_c, why_c = _online(cC, tries=4, gap=4) if okc else (False, "dial refused")
        st_live.log = (f"A/{pa}: ok={oka} online={on_a} {why_a}\n"
                       f"B/{pb}: ok={okb} online={on_b} {why_b}\n"
                       f"C/{pc}: ok={okc} online={on_c} {why_c}\n"
                       f"== C dial ==\n{lc[-1500:]}")
        if not (on_a and on_b):
            st_live.status = Status.NA
            st_live.detail = (f"the first {_IP_CAP} devices could not both get online "
                              f"({pa}={on_a}, {pb}={on_b}), so the cap cannot be judged")
        elif on_c:
            st_live.status = Status.FAIL
            st_live.detail = (f"a 3rd address reached the internet over {pc} under an "
                              f"ipLimit of {_IP_CAP}: the cap is not counted across the "
                              f"account's inbounds")
        else:
            st_live.status = Status.PASS
            st_live.detail = (f"{pa}+{pb} served on 2 addresses, the 3rd ({pc}, a different "
                              f"inbound of the same account) was cut off at ipLimit={_IP_CAP}")
        log(f"-> ip-limit-counts-across-inbounds [{st_live.status.value}] {st_live.detail}")
    except Exception as e:  # noqa: BLE001
        for st in (st_pub, st_live, st_vpn):
            if st.status == Status.SKIP:
                st.status, st.detail = Status.ERROR, str(e)[:250]
    finally:
        for c, p in ((cA, picks[0] if picks else None),
                     (cB, picks[1] if len(picks) > 1 else None),
                     (cC, picks[2] if len(picks) > 2 else None)):
            if c is not None and p:
                _hangup(c, p)
        try:
            panel.update_client(anchor.inbound_id, EMAIL, {"limitIp": 0},
                                inbound_ids=_member_ids(sc))
            time.sleep(8)
        except Exception as e:  # noqa: BLE001
            log(f"   (ip-limit cleanup failed: {e})")


def _wait_account_enabled(panel, sc, log, timeout: int = 90) -> tuple[bool, str]:
    """Re-enable the account and WAIT until the panel agrees it is on.

    Both halves are checked because both are read by somebody: client_traffics.enable
    is what RADIUS and the rbridge sweep consult, and the projected entries are what
    the core and every daemon config writer consult. A step that needs a live account
    has to see both, and a fixed sleep does not guarantee either."""
    anchor = _inbound_of(sc, "vless")
    ids = _member_ids(sc)
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            panel.update_client(anchor.inbound_id, EMAIL, {"enable": True}, inbound_ids=ids)
        except Exception as e:  # noqa: BLE001
            last = f"the re-enable write failed: {str(e)[:150]}"
            time.sleep(8)
            continue
        time.sleep(10)
        row = panel.get_client_traffics(EMAIL) or {}
        # The ACCOUNT row as well, because getClientTraffics is not authoritative
        # here: it reconciles `enable` in memory from GetClientByEmail
        # (inbound.go:4452), which for a multi-inbound account picks an arbitrary
        # membership, so it can report enabled while the account row is not.
        rows = (panel.list_accounts(search=EMAIL) or {}).get("rows") or []
        acct = next((r for r in rows if (r.get("email") or "").lower() == EMAIL), {})
        off = []
        for proto in ORDER:
            ib = _inbound_of(sc, proto)
            if ib is None:
                continue
            entry = panel.get_client(ib.inbound_id, EMAIL)
            if entry and not entry.get("enable"):
                off.append(proto)
        if acct.get("enable") and row.get("enable") and not off:
            return True, ""
        last = (f"account.enable={acct.get('enable')}, "
                f"client_traffics.enable={row.get('enable')}, "
                f"memberships still off: {off[:6]}")
        log(f"   (waiting for the account to come back on: {last})")
    return False, last


def _desync_check(cA, sc, panel, phase, ready, log) -> None:
    """A client write that does NOT name the membership set updates the ACCOUNT and
    re-projects only the inbound it was posted to.

    The account row is the source of truth for quota / expiry / enable, but nothing
    enforces from it: Xray builds each inbound's user list from that inbound's
    settings.clients, and every VPN daemon config writer reads the same JSON. So the
    account can read disabled while eight of its nine memberships still say
    enable:true and keep serving traffic - the exact "live account nobody is billed
    for" state ApplyMemberships' own comment says the layer exists to prevent.

    Reachable from the panel's own UI, not just the API: the per-membership enable
    switch on the Clients page (clients.html:323 -> clientActions.switchEnableClient)
    calls updateClient with no inboundIds.

    Asserted here on `enable` because that one has a live consequence in the same run;
    totalGB and limitIp de-sync identically. Restored through the membership set
    afterwards so the sweeps that follow see a consistent account."""
    anchor = _inbound_of(sc, "vless")
    st = phase.add(SubTest("single-inbound-write-fans-out"))
    if anchor is None:
        st.status, st.detail = Status.SKIP, "no vless anchor"
        return
    try:
        panel.update_client(anchor.inbound_id, EMAIL, {"enable": False})
        time.sleep(8)
        rows = (panel.list_accounts(search=EMAIL) or {}).get("rows") or []
        acct = next((r for r in rows if (r.get("email") or "").lower() == EMAIL), {})
        stale = []
        for proto in ORDER:
            ib = _inbound_of(sc, proto)
            if ib is None:
                continue
            entry = panel.get_client(ib.inbound_id, EMAIL)
            if entry and entry.get("enable"):
                stale.append(proto)
        st.log = (f"account row after a single-inbound disable: "
                  f"enable={acct.get('enable')} totalGB={acct.get('totalGB')}\n"
                  f"memberships still reading enable=true: {stale}")
        if acct.get("enable") is False and stale:
            st.status = Status.FAIL
            st.detail = (f"the account row reads enable=false while {len(stale)} of its "
                         f"memberships still read enable=true ({', '.join(stale[:6])}"
                         f"{'…' if len(stale) > 6 else ''}): a write that omits "
                         f"inboundIds updates the account but re-projects only the "
                         f"inbound it was posted to")
        elif not stale:
            st.status = Status.PASS
            st.detail = "a single-inbound write re-projected every membership"
        else:
            st.status = Status.PASS
            st.detail = (f"the write did not reach the account row either "
                         f"(enable={acct.get('enable')}), so nothing de-synced")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:250]
    log(f"-> single-inbound-write-fans-out [{st.status.value}] {st.detail}")

    # What that de-sync actually DOES, live. The two halves of the account are read by
    # different enforcers, so a half-applied write does not simply "not take effect":
    #
    #   * updateClient runs UpdateClientStat, which writes client_traffics.enable - one
    #     row per EMAIL, panel-wide. RADIUS reads it (radius.go:769) and so does the
    #     rbridge sweep (radius.go:701), so every VPN protocol goes dark at once.
    #   * the Xray-native protocols are served from each inbound's settings.clients,
    #     which the skipped projection left saying enable:true, so they keep serving.
    #
    # One switch, opposite outcomes on the two halves of the same account, and neither
    # is what the control says it does. Recorded as a real per-family observation
    # rather than a pass/fail on a guess about which behaviour was intended.
    st_live = phase.add(SubTest("single-inbound-disable-live-effect"))
    try:
        served = {}
        for proto in _one_per_family(ready):
            if abort.is_set():
                break
            if proto in PROBE_ONLY:
                ib = _inbound_of(sc, proto)
                verdict, _, _ = mt_mod.probe(cA, ib, "M", "classic", sc.server_ip)
                served[proto] = (verdict == "pass")
                continue
            try:
                ok, _, _ = _dial(cA, sc, panel, proto)
                served[proto] = bool(ok) and _online(cA, tries=2, gap=3)[0]
            finally:
                _hangup(cA, proto)
        on = sorted(p for p, v in served.items() if v)
        off = sorted(p for p, v in served.items() if not v)
        st_live.log = (f"after disabling ONE membership (the {anchor.protocol} one), by "
                       f"enforcement family: still served={on}, cut off={off}")
        if on and off:
            st_live.status = Status.FAIL
            st_live.detail = (f"disabling ONE membership cut the account off on {off} "
                              f"while {on} kept serving it: client_traffics.enable is "
                              f"panel-wide so the RADIUS/sweep protocols all stopped, "
                              f"and the Xray-native ones read the settings.clients the "
                              f"skipped projection left at enable:true")
        elif on:
            st_live.status = Status.FAIL
            st_live.detail = (f"the account was disabled and every protocol tested still "
                              f"served it ({on})")
        else:
            st_live.status = Status.PASS
            st_live.detail = f"every enforcement family stopped serving the account ({off})"
    except Exception as e:  # noqa: BLE001
        st_live.status, st_live.detail = Status.ERROR, str(e)[:250]
    log(f"-> single-inbound-disable-live-effect [{st_live.status.value}] {st_live.detail}")

    # The account comes back on before the next check, which is the whole reason that
    # check exists: it asks whether ONE membership can go dark on its own, and the
    # projection renders the AND of the account flag and the membership flag. Leave
    # the account down from the disable above and all 18 render disabled no matter
    # what the switch does, so the assertion would fail against correct code.
    ok, why = _wait_account_enabled(panel, sc, log)
    if not ok:
        st_pre = phase.add(SubTest("per-membership-toggle-precondition"))
        st_pre.status = Status.ERROR
        st_pre.detail = f"the account would not come back on, so the switch is untestable: {why}"
        log(f"-> per-membership-toggle-precondition [error] {st_pre.detail}")
        return

    # The per-inbound switch, on its own terms. It is a DIFFERENT question from the
    # account-wide disable above, it has its own route and its own column
    # (account_inbounds.enable), and the projection renders the AND of the two. What
    # has to be true is that exactly one membership goes dark: the account keeps its
    # flag, so nothing that reads client_traffics panel-wide (RADIUS, the rbridge
    # sweep) may fire, and every other inbound keeps serving the customer.
    st2 = phase.add(SubTest("per-membership-toggle-stays-per-membership"))
    target = _pick(ready, ORDER)                       # the one to switch off
    other = _pick(ready, ORDER, exclude=(target,))     # one that must keep serving
    if not target or not other:
        st2.status, st2.detail = Status.SKIP, "need two working protocols"
        log(f"-> per-membership-toggle-stays-per-membership [skip] {st2.detail}")
        return
    tib = _inbound_of(sc, target)
    try:
        # The ACCOUNT row IMMEDIATELY before the switch. _wait_account_enabled above
        # judges readiness partly from getClientTraffics, and that endpoint
        # reconciles `enable` in memory from GetClientByEmail (inbound.go:4452),
        # picking an arbitrary membership for a multi-inbound account. So it can
        # report an enabled account that is not enabled. This read is the accounts
        # layer's own answer, and it is what says whether the switch lowered the
        # account or merely found it already down.
        rows_before = (panel.list_accounts(search=EMAIL) or {}).get("rows") or []
        before = next((r for r in rows_before
                       if (r.get("email") or "").lower() == EMAIL), {})
        log(f"   (account row immediately BEFORE the switch: enable={before.get('enable')})")
        panel.set_membership_enable(tib.inbound_id, EMAIL, False)
        time.sleep(20)
        states = {}
        for proto in ORDER:
            ib = _inbound_of(sc, proto)
            if ib is None:
                continue
            entry = panel.get_client(ib.inbound_id, EMAIL)
            if entry:
                states[proto] = bool(entry.get("enable"))
        dark = sorted(p for p, on in states.items() if not on)
        row = (panel.get_client_traffics(EMAIL) or {})
        # The ACCOUNT row as the accounts layer holds it, which is what actually
        # decides the projection. getClientTraffics is not a substitute: that endpoint
        # reconciles `enable` in memory from GetClientByEmail (inbound.go:4452), and
        # for a multi-inbound account that picks an arbitrary membership, so it can
        # report a disabled account that is not disabled.
        rows = (panel.list_accounts(search=EMAIL) or {}).get("rows") or []
        acct = next((r for r in rows if (r.get("email") or "").lower() == EMAIL), {})
        # Read the memberships again after a further settle. If the first read caught
        # an in-flight reconcile, the second disagrees and the verdict follows it.
        time.sleep(15)
        later = {}
        for proto in ORDER:
            ib = _inbound_of(sc, proto)
            if ib is None:
                continue
            entry = panel.get_client(ib.inbound_id, EMAIL)
            if entry:
                later[proto] = bool(entry.get("enable"))
        dark_later = sorted(p for p, on in later.items() if not on)
        st2.log = (f"switched {target} off\n"
                   f"  ACCOUNT row BEFORE : enable={before.get('enable')}\n"
                   f"  memberships @+20s : {states}\n"
                   f"  memberships @+35s : {later}\n"
                   f"  ACCOUNT row       : enable={acct.get('enable')} "
                   f"totalGB={acct.get('totalGB')} up={acct.get('up')} down={acct.get('down')}\n"
                   f"  client_traffics   : {json.dumps(row)}")
        if dark != dark_later:
            log(f"   (memberships settled differently: {dark} -> {dark_later})")
            dark = dark_later
        if dark != [target]:
            st2.status = Status.FAIL
            st2.detail = (f"switching {target} off left {dark or 'nothing'} disabled, "
                          f"want exactly ['{target}']: the per-inbound switch is still "
                          f"writing the account-wide flag")
        elif not row.get("enable", True):
            st2.status = Status.FAIL
            st2.detail = (f"only {target} was switched off but the account's traffic row "
                          f"reads enable=false, so RADIUS and the rbridge sweep will cut "
                          f"the customer off everywhere")
        else:
            # Prove it live: the switched-off inbound refuses, the other still serves.
            off_ok, _, _ = _dial(cA, sc, panel, target)
            off_online = _online(cA, tries=2, gap=3)[0] if off_ok else False
            _hangup(cA, target)
            on_ok, _, _ = _dial(cA, sc, panel, other)
            on_online = _online(cA, tries=5, gap=4)[0] if on_ok else False
            _hangup(cA, other)
            st2.log += f"\nlive: {target} online={off_online}, {other} online={on_online}"
            if off_online:
                st2.status = Status.FAIL
                st2.detail = f"{target} was switched off and still carried traffic"
            elif not on_online:
                st2.status = Status.FAIL
                st2.detail = (f"switching {target} off also took {other} down: the switch "
                              f"is not per-inbound")
            else:
                st2.status = Status.PASS
                st2.detail = (f"{target} alone went dark and {other} kept serving the same "
                              f"account, with the account flag untouched")
    except Exception as e:  # noqa: BLE001
        st2.status, st2.detail = Status.ERROR, str(e)[:250]
    finally:
        try:
            panel.set_membership_enable(tib.inbound_id, EMAIL, True)
            panel.update_client(anchor.inbound_id, EMAIL, {"enable": True},
                                inbound_ids=_member_ids(sc))
            time.sleep(15)
        except Exception as e:  # noqa: BLE001
            log(f"   (per-membership cleanup failed: {e})")
    log(f"-> per-membership-toggle-stays-per-membership [{st2.status.value}] {st2.detail}")


# ---------------------------------------------------------------------------
# stage 8: credentials that CANNOT be shared
# ---------------------------------------------------------------------------
def _ss2022_credential_check(panel, sc, phase, log) -> None:
    """The accounts layer keeps ONE password per account and hands it to every
    protocol that keys on a password. Shadowsocks-2022 is the one member of that group
    whose password is not a free string: the per-user PSK must be base64 of exactly
    the cipher's key length, and ensureCredentialsFor only mints when the field is
    EMPTY. So an account that already holds a password (from openvpn, trojan, anytls,
    naive or a non-2022 shadowsocks) and then joins a 2022 inbound keeps the password
    it had - which that inbound cannot use.

    Run last, and on a throwaway inbound that is deleted afterwards: an unusable PSK
    is not a quiet per-account failure, it can make the core refuse the whole
    configuration, which would take every Xray-native protocol down with it."""
    st = phase.add(SubTest("shadowsocks-2022-shared-password"))
    iid = None
    try:
        inb = panel.add_inbound(
            "test-ss2022", HYSTERIA_PORT + 1, "shadowsocks",
            {"clients": [], "method": "2022-blake3-aes-256-gcm",
             "password": _b64_32(),
             "network": "tcp,udp"},
            stream={"network": "tcp", "security": "none"})
        iid = inb.get("id")
        ids = _member_ids(sc) + [iid]
        anchor = _inbound_of(sc, "vless")
        panel.update_client(anchor.inbound_id, EMAIL, {}, inbound_ids=ids)
        time.sleep(8)
        entry = panel.get_client(iid, EMAIL)
        pw = str(entry.get("password") or "")
        st.log = json.dumps(entry)[:800]
        ok, why = _valid_ss2022_psk(pw, 32)
        if ok:
            st.status = Status.PASS
            st.detail = "joining a 2022-blake3 inbound minted a PSK of the right shape"
        else:
            st.status = Status.FAIL
            st.detail = (f"the account joined a 2022-blake3-aes-256-gcm inbound with the "
                         f"password it already had ({_ellipsis(pw, 12)}): {why}. That "
                         f"account cannot connect on this inbound.")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:250]
    finally:
        if iid:
            try:
                panel.update_client(_inbound_of(sc, "vless").inbound_id, EMAIL, {},
                                    inbound_ids=_member_ids(sc))
                time.sleep(4)
                panel.del_inbound(iid)
                time.sleep(6)
            except Exception as e:  # noqa: BLE001
                log(f"   (ss2022 cleanup failed: {e})")
    log(f"-> shadowsocks-2022-shared-password [{st.status.value}] {st.detail}")


def _b64_32() -> str:
    import base64
    import os as _os
    return base64.b64encode(_os.urandom(32)).decode()


def _valid_ss2022_psk(pw: str, want_bytes: int) -> tuple[bool, str]:
    import base64
    import binascii
    try:
        raw = base64.b64decode(pw, validate=True)
    except (ValueError, binascii.Error):
        return False, "not valid base64"
    if len(raw) != want_bytes:
        return False, f"decodes to {len(raw)} bytes, the cipher needs exactly {want_bytes}"
    return True, ""


def _hysteria_membership_check(panel, sc, phase, log) -> None:
    """Hysteria is the one account-bearing protocol with no client driver anywhere in
    this harness (its client is not xray), so it cannot be dialled here. What CAN be
    tested is the half this phase is about: that the accounts layer mints its `auth`
    credential and projects the account onto it. Isolated on a throwaway inbound,
    deleted afterwards, and run last for the same reason as the 2022 check."""
    st = phase.add(SubTest("hysteria-membership-projection"))
    iid = None
    try:
        inb = panel.add_inbound("test-hysteria", HYSTERIA_PORT, "hysteria",
                                {"clients": [], "up_mbps": 100, "down_mbps": 100,
                                 "obfs": ""},
                                stream=server_setup._xray_stream(panel, "hysteria"))
        iid = inb.get("id")
        ids = _member_ids(sc) + [iid]
        anchor = _inbound_of(sc, "vless")
        panel.update_client(anchor.inbound_id, EMAIL, {}, inbound_ids=ids)
        time.sleep(8)
        entry = panel.get_client(iid, EMAIL)
        st.log = json.dumps(entry)[:800]
        if not entry:
            st.status, st.detail = Status.FAIL, "the account was not projected onto the hysteria inbound"
        elif not str(entry.get("auth") or "").strip():
            st.status = Status.FAIL
            st.detail = "projected with an EMPTY auth: a hysteria membership has no credential"
        else:
            st.status = Status.PASS
            st.detail = (f"auth={_ellipsis(str(entry.get('auth')))} minted on join "
                         f"(not dialled: no hysteria client in this harness)")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.NA, f"hysteria inbound could not be created: {str(e)[:180]}"
    finally:
        if iid:
            try:
                panel.update_client(_inbound_of(sc, "vless").inbound_id, EMAIL, {},
                                    inbound_ids=_member_ids(sc))
                time.sleep(4)
                panel.del_inbound(iid)
                time.sleep(6)
            except Exception as e:  # noqa: BLE001
                log(f"   (hysteria cleanup failed: {e})")
    log(f"-> hysteria-membership-projection [{st.status.value}] {st.detail}")


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------
def run(cA, cB, cC, sc, cfg, result, panel=None, server_exec=None, log=None) -> None:
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_MULTI)
    if panel is None or sc is None:
        phase.add(SubTest("phase", Status.ERROR, "no panel / no server setup"))
        return

    _build_classic(panel, sc, phase, log)
    created, ids = _create_account(panel, sc, phase, log)
    if not created:
        phase.add(SubTest("phase", Status.SKIP,
                          "the account could not be created; nothing below can run"))
        return
    # The membership fan-out reconciles every protocol in the union of the old and new
    # sets: config writers, daemon restarts and an Xray restart. Let it land before
    # anything dials.
    time.sleep(25)

    _verify_memberships(panel, sc, phase, ids, log)
    ready = _adopt_credentials(panel, sc, phase, log)
    _check_mtproto_membership(panel, sc, phase, log)
    log(f":: multi-inbound — {len(ready)} of {len(ORDER)} protocols have a usable "
        f"projected credential: {', '.join(ready)}")

    if abort.is_set():
        return
    deltas = _sweep_connect_and_count(cA, sc, panel, cfg, phase, ready, log)
    _one_counter_check(panel, sc, phase, deltas, log)

    if abort.is_set():
        return
    _multiplier_check(cA, sc, panel, cfg, phase, ready, log)

    if abort.is_set():
        return
    _ip_limit_check(cA, cB, cC, sc, panel, phase, ready, server_exec, log)

    if abort.is_set():
        return
    # Suspension by OPERATOR first (the flag on its own), then by QUOTA (the flag as a
    # consequence). Both end in the same state, so the expensive per-protocol sweep is
    # run once, against the operator case, where the cause is unambiguous.
    anchor = _inbound_of(sc, "vless") or _inbound_of(sc, ORDER[0])
    try:
        panel.update_client(anchor.inbound_id, EMAIL, {"enable": False},
                            inbound_ids=_member_ids(sc))
        time.sleep(20)
    except Exception as e:  # noqa: BLE001
        phase.add(SubTest("suspend-set", Status.ERROR, str(e)[:200]))
    _projection_enable_check(panel, sc, phase, "suspend-reaches-every-membership", False, log)
    _suspend_sweep(cA, sc, panel, phase, ready, log, tag="suspended")

    try:
        panel.update_client(anchor.inbound_id, EMAIL, {"enable": True},
                            inbound_ids=_member_ids(sc))
        time.sleep(20)
    except Exception as e:  # noqa: BLE001
        phase.add(SubTest("resume-set", Status.ERROR, str(e)[:200]))
    _projection_enable_check(panel, sc, phase, "resume-reaches-every-membership", True, log)
    _restore_sweep(cA, sc, panel, phase, ready, log)

    if abort.is_set():
        return
    disabled = _limit_check(cA, sc, panel, cfg, phase, ready, log)
    if disabled:
        # One protocol per enforcement family rather than all 18: the depletion sweep
        # reaches every inbound serving the email through the same code for all of
        # them (inboundsServingEmails), and the per-protocol cost was already paid on
        # the operator-suspend sweep above.
        _suspend_sweep(cA, sc, panel, phase, ready, log, tag="over-quota",
                       only=_one_per_family(ready))
    # Leave the account usable for anything that runs after this phase.
    try:
        panel.update_client(anchor.inbound_id, EMAIL, {"totalGB": 0, "enable": True},
                            inbound_ids=_member_ids(sc))
        panel.reset_client_traffic(anchor.inbound_id, EMAIL)
        time.sleep(10)
    except Exception as e:  # noqa: BLE001
        log(f"   (quota cleanup failed: {e})")

    if abort.is_set():
        return
    _desync_check(cA, sc, panel, phase, ready, log)
    _ss2022_credential_check(panel, sc, phase, log)
    _hysteria_membership_check(panel, sc, phase, log)
