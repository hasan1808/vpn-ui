"""Subscription E2E (pure panel/HTTP API — no tunnels).

Turns the subscription server on, then for every protocol inbound gives an account a
subId + quota + expiry and fetches the account's subscription off the dedicated sub
server. Asserts, per feature × per protocol:

  * stats — the `Subscription-Userinfo` header carries the account's quota + expiry for
    EVERY protocol (the remaining-days/traffic the subscriber page renders);
  * raw link — the right per-protocol representation is present: native `vmess://`,
    MTProto `tg://`, SSH `ssh://`, wg-c/awg `wireguard://`, the Xray-native three
    `anytls://` / `tuic://` / `naive+…://`, and the credential VPNs
    (openvpn/l2tp/pptp/openconnect/sstp/ikev2) a `trojan://` connection card whose name
    carries "<Label> user=… pass=…". Where a link is useless without a specific
    parameter, that parameter is asserted too (LINK_MUST_CARRY: tuic's `alpn=h3`);
  * importable — EVERY protocol leaves at least one entry a subscription client can
    parse, so the group is never imported empty and the quota header has something to
    attach to (mtproto/ssh carry their native link plus that card);
  * clash — wg-c/awg appear in the Clash sub as `type: wireguard` (their full .conf,
    obfuscation included, only fits there);
  * json — the Xray-JSON sub carries the native protocols and cleanly OMITS the new
    ones (the guard that stops broken no-outbound entries).

Runs after backup-restore (it enables the sub + restarts the panel), before warp.
"""
from __future__ import annotations

import json
import socket
import time
import uuid
from urllib.parse import unquote

from .model import SubTest, Status, PHASE_SUBSCRIPTION

GB = 1024 ** 3

# protocol -> substring that MUST appear in the RAW sub, matched against the
# percent-DECODED body (the connection-card names arrive as %20-escaped fragments).
RAW_MARKER = {
    "openvpn": "OpenVPN user=",
    "l2tp": "L2TP/IPsec user=",
    "pptp": "PPTP user=",
    "openconnect": "OpenConnect user=",
    "sstp": "SSTP user=",
    "ikev2": "IKEv2 user=",
    "mtproto": "tg://proxy?server=",
    "ssh": "ssh://",
    "wg-c": "wireguard://",
    "awg": "wireguard://",
    # Xray-native: their own native schemes, so no connection card is involved.
    "anytls": "anytls://",
    "tuic": "tuic://",
    # `naive+https://` (h2) or `naive+quic://` (h3): the scheme half is decided by the
    # inbound's `network`, so match the prefix both share rather than pinning the one
    # this harness happens to configure.
    "naive": "naive+",
}
# TUIC's server side pins ALPN to h3, and sing-box / mihomo / the Rust tuic-client all
# default to sending NO ALPN, which fails the handshake with an opaque
# "tls: no application protocol" that names nothing an operator can act on. So the
# share link carrying alpn=h3 is not cosmetic, it is what makes the link usable at all,
# and it is asserted separately from the scheme above.
LINK_MUST_CARRY = {"tuic": ("alpn=h3",)}
# Every protocol must leave at least one line a subscription client can actually parse,
# or the account imports as an empty group with no quota attached.
IMPORTABLE_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://", "wireguard://",
                      "hysteria://", "hysteria2://",
                      # The Xray-native three carry their OWN scheme and no connection
                      # card: unlike a credential VPN (whose "link" is just a name with
                      # user=/pass= in it) these are real proxy URIs that sing-box,
                      # mihomo and v2rayN import directly, so the scheme IS the
                      # importable entry.
                      "anytls://", "tuic://", "naive+https://", "naive+quic://")
CLASH_WG = {"wg-c", "awg"}


def _userinfo(headers) -> dict:
    """Parse `Subscription-Userinfo: upload=..; download=..; total=..; expire=..`."""
    out = {}
    for part in headers.get("Subscription-Userinfo", "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            try:
                out[k.strip()] = int(v.strip())
            except ValueError:
                pass
    return out


def run(panel, sc, cfg: dict, result, log=None) -> None:
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_SUBSCRIPTION)

    def subtest(name, body):
        st = phase.add(SubTest(name))
        try:
            ok, detail = body()
            st.status = Status.PASS if ok else Status.FAIL
            st.detail = detail
        except Exception as e:  # noqa: BLE001
            st.status, st.detail = Status.ERROR, str(e)[:200]
        log(f"-> {st.name} [{st.status.value}] {st.detail}")
        return st.status

    panel_timeout = cfg.get("vm", {}).get("panel_timeout", 300)
    server_ip = sc.server_ip
    expiry_ms = (int(time.time()) + 30 * 86400) * 1000
    total = 10 * GB
    state = {}

    # --- 1. enable the sub server + restart so it binds --------------------
    def _enable():
        panel.enable_subscription()
        # The sub server only binds when subEnable is true; confirm it persisted.
        chk = panel.get_all_settings()
        se = chk.get("subEnable")
        if se not in (True, "true", "True", 1, "1"):
            return False, f"subEnable did not persist through the settings update (got {se!r})"
        state["port"] = int(chk.get("subPort", 2097))
        state["sub"] = chk.get("subPath", "/sub/")
        state["json"] = chk.get("subJsonPath", "/json/")
        state["clash"] = chk.get("subClashPath", "/clash/")
        panel.restart_panel_service()
        time.sleep(9)                       # 3s SIGHUP delay + the in-process restart
        panel.wait_up(panel_timeout)
        panel.login()
        # The sub server binds a moment after the panel on the SIGHUP restart; poll its
        # port until it accepts a connection rather than racing the first fetch.
        deadline = time.time() + 45
        while time.time() < deadline:
            try:
                socket.create_connection((server_ip, state["port"]), timeout=3).close()
                return True, f"sub server up on {server_ip}:{state['port']} (raw {state['sub']}, json {state['json']}, clash {state['clash']})"
            except OSError:
                time.sleep(2)
        return False, f"sub server never came up on {server_ip}:{state['port']} after the panel restart"

    if subtest("enable+restart", _enable) is not Status.PASS:
        log("-> subscription: sub server not up, skipping the rest")
        return

    port = state["port"]

    # --- 2. native vmess: raw vmess:// + JSON outbound + Clash proxy + stats
    def _vmess():
        sid = "e2esubvmess"
        vs = {"clients": [{"id": str(uuid.uuid4()), "email": "e2e-sub-vmess",
                           "subId": sid, "totalGB": total, "expiryTime": expiry_ms,
                           "enable": True}]}
        panel.add_inbound("e2e-sub-vmess", 24680, "vmess", vs)
        rc, rt, rh = panel.fetch_sub(server_ip, port, state["sub"], sid)
        ui = _userinfo(rh)
        raw_ok = rc == 200 and "vmess://" in rt
        stat_ok = ui.get("total") == total and ui.get("expire") == expiry_ms // 1000
        jc, jt, _ = panel.fetch_sub(server_ip, port, state["json"], sid)
        json_ok = jc == 200 and "vmess" in jt
        cc, ct, _ = panel.fetch_sub(server_ip, port, state["clash"], sid)
        clash_ok = cc == 200 and "vmess" in ct
        ok = raw_ok and stat_ok and json_ok and clash_ok
        return ok, f"raw={raw_ok} stats={stat_ok}(total={ui.get('total')},expire={ui.get('expire')}) json={json_ok} clash={clash_ok}"
    subtest("native-vmess raw+json+clash+stats", _vmess)

    # --- 3. every protocol inbound: stats for ALL + right representation ----
    for proto, ib in list(sc.inbounds.items()):
        marker = RAW_MARKER.get(proto, "__unmapped__")
        sid = "e2esub" + proto.replace("-", "")

        def _one(proto=proto, ib=ib, marker=marker, sid=sid):
            panel.set_client_subscription(ib.inbound_id, sid, total, expiry_ms)
            clash_ok = True
            if proto in CLASH_WG:
                # wg-c/awg also belong in the Clash sub: only there does the full config
                # fit (keys, DNS, and awg's obfuscation block).
                cc, ct, ch = panel.fetch_sub(server_ip, port, state["clash"], sid)
                if cc != 200:
                    return False, f"clash sub HTTP {cc}"
                clash_ok = "type: wireguard" in ct
            rc, rt, rh = panel.fetch_sub(server_ip, port, state["sub"], sid)
            if rc != 200:
                return False, f"raw sub HTTP {rc}"
            ui = _userinfo(rh)
            # The remaining-days/traffic stats must be present for EVERY protocol.
            stat_ok = ui.get("total") == total and ui.get("expire") == expiry_ms // 1000
            decoded = unquote(rt)
            rep_ok = marker in decoded
            # ... and every protocol must leave something a client can import, or the
            # stats above have no group to land on.
            imp_ok = any(line.strip().startswith(IMPORTABLE_SCHEMES)
                         for line in rt.splitlines())
            # Per-protocol parameters a link is USELESS without (see LINK_MUST_CARRY).
            missing = [p for p in LINK_MUST_CARRY.get(proto, ()) if p not in decoded]
            if not (clash_ok and imp_ok and not missing):
                return (False, f"stats={stat_ok} rep[{marker!r}]={rep_ok} "
                               f"importable={imp_ok} clash={clash_ok} "
                               f"missing_link_params={missing}")
            return (stat_ok and rep_ok,
                    f"stats={stat_ok}(total={ui.get('total')},expire={ui.get('expire')}) "
                    f"rep[{marker!r}]={rep_ok} importable=True"
                    + (f" carries={list(LINK_MUST_CARRY[proto])}" if proto in LINK_MUST_CARRY else "")
                    + (f" clash_wireguard={clash_ok}" if proto in CLASH_WG else ""))

        subtest(f"{proto} sub", _one)

    # --- 4. the JSON sub cleanly omits a new protocol (the no-broken-entry guard)
    if "mtproto" in sc.inbounds:
        def _json_omits():
            jc, jt, _ = panel.fetch_sub(server_ip, port, state["json"], "e2esubmtproto")
            # mtproto has no Xray outbound; the JSON sub must not emit an entry for it (a
            # mtproto-only subId yields an empty/400 JSON sub, never a broken config).
            ok = "mtproto" not in jt
            return ok, f"json has no mtproto entry (HTTP {jc}, len={len(jt)})"
        subtest("json omits new-protocol", _json_omits)
