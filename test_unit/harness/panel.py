"""HTTP client for the vpn-ui panel.

Grounded in the actual controllers:
  - Auth: POST /login (form), server-side session, cookie "vpn-ui". Reuse jar.
  - All POST handlers bind via c.ShouldBind / c.PostForm -> send
    application/x-www-form-urlencoded, NOT JSON.
  - Response envelope: {"success":bool,"msg":str,"obj":any}. Data in "obj".
  - Paths are prefixed by webBasePath (default "/").
"""
from __future__ import annotations

import json
import time

import requests

from . import abort


class PanelError(RuntimeError):
    pass


# The panel-wide client identity: the value that goes in the URL of
# /panel/api/inbounds/updateClient/:clientId and /:id/delClient/:clientId.
#
# Mirrors clientIdentityKey() in web/service/inbound.go (and its browser twin,
# getClientIdentity in web/assets/js/model/inbound.js). Posting the wrong field is not
# an error the caller sees as a mismatch: the panel answers "empty client ID", or
# worse, HTTP 200 with success:false, so a test that ignored the envelope would read a
# silently skipped write as a pass.
_IDENTITY_PASSWORD = ("trojan", "l2tp", "pptp", "openvpn", "openconnect", "sstp",
                      "ikev2", "anytls", "naive")


def client_identity(protocol: str, client: dict) -> str:
    """The field `client` is addressed by under `protocol`."""
    if protocol in _IDENTITY_PASSWORD:
        return client.get("password", "") or ""
    if protocol == "shadowsocks":
        return client.get("email", "") or ""
    if protocol in ("hysteria", "hysteria2"):
        return client.get("auth", "") or ""
    # vmess/vless/tuic (uuid) and the email-identity protocols (wg-c, awg, gre,
    # mtproto, ssh), whose settings JSON carries id=email.
    return client.get("id", "") or client.get("email", "") or ""


class Panel:
    def __init__(self, host: str, port: int = 2083, base_path: str = "/",
                 scheme: str = "http", username: str = "admin",
                 password: str = "admin", timeout: int = 30):
        bp = base_path if base_path.startswith("/") else "/" + base_path
        if not bp.endswith("/"):
            bp += "/"
        self.host = host
        self.port = port
        self.scheme = scheme
        self._bp = bp
        self.root = f"{scheme}://{host}:{port}{bp}".rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.s = requests.Session()
        # Test panels (local VMs and remote boxes) serve HTTPS with a self-signed cert;
        # the harness is the trusted operator, so skip verification.
        self.s.verify = False
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def set_host(self, host: str):
        """Repoint at a new host (e.g. after a reboot changed the DHCP lease)."""
        self.host = host
        self.root = f"{self.scheme}://{host}:{self.port}{self._bp}".rstrip("/")

    # ---- low level ------------------------------------------------------
    def _url(self, path: str) -> str:
        return f"{self.root}/{path.lstrip('/')}"

    def _post(self, path: str, data: dict) -> dict:
        # Surface transport failures (a dead/OOM-killed panel -> ConnectionError,
        # a hung one -> Timeout) as PanelError, which every caller already handles.
        # Otherwise a raw requests exception escapes to the orchestrator as a hard
        # ERROR even when the caller means to degrade gracefully (e.g. warp NA).
        try:
            r = self.s.post(self._url(path), data=data, timeout=self.timeout)
        except requests.RequestException as e:
            raise PanelError(f"{path} -> transport error: {e}") from e
        return self._envelope(r, path)

    def _get(self, path: str) -> dict:
        try:
            r = self.s.get(self._url(path), timeout=self.timeout)
        except requests.RequestException as e:
            raise PanelError(f"{path} -> transport error: {e}") from e
        return self._envelope(r, path)

    def _envelope(self, r: requests.Response, path: str) -> dict:
        if r.status_code == 404:
            raise PanelError(f"{path} -> 404 (not logged in, or wrong base_path)")
        try:
            body = r.json()
        except ValueError:
            raise PanelError(f"{path} -> non-JSON ({r.status_code}): {r.text[:200]}")
        if not body.get("success", False):
            raise PanelError(f"{path} failed: {body.get('msg')}")
        return body

    # ---- connectivity / auth -------------------------------------------
    def wait_up(self, timeout: int):
        """Wait until the panel answers (login page reachable)."""
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            if abort.is_set():
                raise PanelError("aborted while waiting for panel (Ctrl+C)")
            try:
                r = self.s.get(self._url("/"), timeout=5)
                if r.status_code < 500:
                    return
            except requests.RequestException as e:
                last = str(e)
            time.sleep(2)
        raise PanelError(f"panel not reachable at {self.root} in {timeout}s: {last}")

    def login(self):
        body = self._post("/login", {
            "username": self.username,
            "password": self.password,
        })
        return body

    # ---- provisioning (core-init) --------------------------------------
    def provision_start(self) -> dict:
        return self._post("/panel/core/provision", {}).get("obj", {})

    def provision_status(self) -> dict:
        return self._get("/panel/core/provision-status").get("obj", {})

    def reboot(self):
        # Fire and forget; the machine goes down. Ignore transport errors.
        try:
            self._post("/panel/core/reboot", {})
        except (PanelError, requests.RequestException):
            pass

    def core_status(self) -> dict:
        return self._get("/panel/core/status").get("obj", {})

    def core(self, name: str) -> dict:
        """One core's status dict from /panel/core/status ({} if absent). Each has
        name/state/version/inbounds/detail. IPsec is its own core named "ipsec"
        (state=running -> ipsec.service active; state=not_installed -> no libreswan)."""
        for c in self.core_status().get("cores", []) or []:
            if c.get("name") == name:
                return c
        return {}

    def core_logs(self, core: str) -> str:
        return self._get(f"/panel/core/logs/{core}").get("obj", "") or ""

    def restart_core(self, core: str):
        self._post(f"/panel/core/restart/{core}", {})

    def stop_core(self, core: str):
        self._post(f"/panel/core/stop/{core}", {})

    # ---- inbounds / clients --------------------------------------------
    def add_inbound(self, remark: str, port: int, protocol: str,
                    settings: dict, listen: str = "",
                    stream: dict | None = None) -> dict:
        """Create an inbound. Returns the created inbound dict (has 'id').

        `stream` is the Xray streamSettings block. Every VPN/relay protocol leaves
        it empty (they are served by their own daemon, not by a transport), but the
        Xray-NATIVE protocols carry theirs there: it is where TLS lives, and for
        tuic it also selects the transport ("network": "tuic"). Defaults to {} so
        every existing caller is unchanged."""
        body = self._post("/panel/api/inbounds/add", {
            "remark": remark,
            "enable": "true",
            "listen": listen,
            "port": str(port),
            "protocol": protocol,
            "settings": json.dumps(settings),
            "streamSettings": json.dumps(stream or {}),
            "sniffing": "{}",
        })
        return body.get("obj", {})

    def get_inbound(self, inbound_id: int) -> dict:
        return self._get(f"/panel/api/inbounds/get/{inbound_id}").get("obj", {})

    def list_inbounds(self) -> list:
        return self._get("/panel/api/inbounds/list").get("obj", []) or []

    def update_inbound(self, inbound_id: int, remark: str, port: int,
                       protocol: str, settings: dict, listen: str = "",
                       extra: dict | None = None) -> dict:
        """Update an inbound. Partial: an omitted field keeps its stored value.

        The panel binds this POST onto the STORED row, so a body only has to carry
        what it means to change. An explicitly sent falsy value still wins, which
        is how a flag gets turned off.

        That was not always true. The panel used to bind into a fresh struct and
        copy an allowlist onto the stored row unconditionally, so any column this
        body omitted was written back as its zero value: the traffic multiplier and
        its threshold, all four speed-limit columns, the IP limit and strategy, the
        inbound's own total and expiry, and the reset schedule. Twelve fields, with
        nothing reported. Fixed in a59b0585.

        The three traffic-multiplier columns below are still read from the current
        row and echoed back. They are redundant against a current panel and are
        kept deliberately, because this harness is also pointed at older builds
        during upgrade testing, where the echo is the only thing protecting them.
        Note it never covered the other nine, so an update through this helper
        against a pre-a59b0585 panel did silently wipe those.

        `extra` overrides the pass-through.
        """
        cur = self.get_inbound(inbound_id) or {}
        body = {
            "id": str(inbound_id),
            "remark": remark,
            "enable": "true",
            "listen": listen,
            "port": str(port),
            "protocol": protocol,
            "settings": json.dumps(settings),
            # Echoed from the current row, NOT hardcoded to "{}".
            #
            # It used to be hardcoded, and that was the sharpest edge in this file:
            # the panel copied it onto the stored row unconditionally, so every
            # update through this helper stripped the inbound's whole transport,
            # TLS included. It went unnoticed because every VPN and relay protocol
            # leaves streamSettings empty; on an Xray-native inbound (vless, vmess,
            # trojan, shadowsocks, hysteria, anytls, tuic, naive) the next client
            # got "connection reset by peer", which reads as a broken protocol
            # rather than a wiped transport. Callers had to remember to pass it in
            # `extra`, and a caller who forgot got no warning.
            #
            # Echoing rather than omitting on purpose: omitting is correct against
            # a current panel (a59b0585 makes an absent field mean "leave alone")
            # but would still wipe against an older build, and this harness is
            # pointed at older builds during upgrade testing.
            "streamSettings": cur.get("streamSettings", "{}") or "{}",
            "sniffing": cur.get("sniffing", "{}") or "{}",
            "trafficMultiplierEnable": "true" if cur.get("trafficMultiplierEnable") else "false",
            "trafficMultiplierAfter": str(int(cur.get("trafficMultiplierAfter") or 0)),
            "trafficMultiplier": str(cur.get("trafficMultiplier") or 1),
        }
        body.update(extra or {})
        return self._post(f"/panel/api/inbounds/update/{inbound_id}", body).get("obj", {})

    def set_traffic_multiplier(self, inbound_id: int, enable: bool,
                               after_bytes: int = 0, multiplier: float = 1) -> dict:
        """Turn an inbound's Traffic Multiplier on/off in place, preserving every
        other setting. Past `after_bytes` of usage, each byte counts `multiplier`
        times against the client's quota; below it, 1:1.

        Re-saving an inbound restarts its daemon, so callers must (re)connect after
        this, not before.

        streamSettings no longer has to be echoed here: update_inbound carries it
        from the current row itself. It used to hardcode "{}", which silently
        stripped the transport (TLS included) off every Xray-native inbound this
        touched."""
        ib = self.get_inbound(inbound_id)
        return self.update_inbound(
            inbound_id,
            ib.get("remark", ""),
            ib.get("port", 0),
            ib.get("protocol", ""),
            json.loads(ib.get("settings") or "{}"),
            ib.get("listen", "") or "",
            extra={
                "trafficMultiplierEnable": "true" if enable else "false",
                "trafficMultiplierAfter": str(int(after_bytes)),
                "trafficMultiplier": str(multiplier),
            },
        )

    def set_user_limit_strategy(self, inbound_id: int, strategy: str):
        """Flip an existing inbound's User Limit Strategy ('reject'/'accept') in
        place, preserving every other setting. Re-saving triggers the panel's
        on<Proto>Changed hook: GenerateAllConfigs (rewrites the openvpn
        strategy-<proto> file / blocks) + RestartServices (daemon restart = clean
        slate). L2TP/PPTP additionally read the strategy live from the DB per auth."""
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        settings["userLimitStrategy"] = strategy
        self.update_inbound(
            inbound_id,
            ib.get("remark", ""),
            ib.get("port", 0),
            ib.get("protocol", ""),
            settings,
            ib.get("listen", "") or "",
        )

    def add_client(self, inbound_id: int, client: dict, inbound_ids=None):
        """Add one client (username/password account) to an inbound.

        `inbound_ids` names every inbound the ACCOUNT should be served on (the
        multi-inbound membership set). It is posted as a REPEATED `inboundIds` form
        key, which is what Qs.stringify emits with arrayFormat 'repeat' and what the
        panel binds with c.PostFormArray. Omitting it entirely is the legacy
        single-inbound path and is what every existing caller does; the target
        inbound is always in the set whether or not it is repeated here."""
        data = {
            "id": str(inbound_id),
            "settings": json.dumps({"clients": [client]}),
        }
        if inbound_ids is not None:
            # requests encodes a list value as repeated keys, exactly the wire shape
            # postedMembershipIds reads. An EMPTY list must still post one empty value:
            # that is the panel's "the group was explicitly cleared" sentinel, and
            # sending no key at all would instead mean "don't touch memberships".
            data["inboundIds"] = [str(i) for i in inbound_ids] or [""]
        return self._post("/panel/api/inbounds/addClient", data)

    def update_client(self, inbound_id: int, email: str, changes: dict,
                      inbound_ids=None) -> dict:
        """Change fields on ONE existing client through /updateClient/:clientId.

        Reads the stored entry first and posts it back with `changes` overlaid, so a
        field this caller does not mention keeps its value. That matters more here
        than it looks: the endpoint takes the whole client object, so a caller that
        rebuilt it from scratch would blank the account's credentials.

        Returns the client dict as posted, for the caller to assert against."""
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        target = None
        for c in settings.get("clients", []):
            if c.get("email") == email:
                target = dict(c)
                break
        if target is None:
            raise PanelError(f"client {email} not found on inbound {inbound_id}")
        target.update(changes)
        proto = ib.get("protocol", "")
        data = {
            "id": str(inbound_id),
            "remark": ib.get("remark", ""),
            "enable": "true",
            "listen": ib.get("listen", "") or "",
            "port": str(ib.get("port", 0)),
            "protocol": proto,
            "settings": json.dumps({"clients": [target]}),
            "streamSettings": "{}",
            "sniffing": "{}",
        }
        if inbound_ids is not None:
            data["inboundIds"] = [str(i) for i in inbound_ids] or [""]
        self._post(f"/panel/api/inbounds/updateClient/{client_identity(proto, target)}", data)
        return target

    def set_membership_enable(self, inbound_id: int, email: str, enable: bool) -> dict:
        """Switch one account on or off on ONE inbound, leaving the others serving.

        Its own route rather than a shape of updateClient because `enable` inside a
        posted client entry is the ACCOUNT's flag: the panel writes it through to
        client_traffics, which RADIUS and the rbridge sweep both read panel-wide."""
        return self._post(
            f"/panel/api/inbounds/{inbound_id}/setMembershipEnable/{email}",
            {"enable": "true" if enable else "false"})

    def list_accounts(self, search: str = "", page: int = 1, size: int = 200) -> dict:
        """The accounts read model behind the Clients page: one row per ACCOUNT with
        its memberships, rather than one row per inbound client entry."""
        q = f"?page={page}&size={size}"
        if search:
            q += f"&search={search}"
        return self._get(f"/panel/api/clients/list{q}").get("obj", {}) or {}

    def del_inbound(self, inbound_id: int):
        """Delete an inbound by id (POST /panel/api/inbounds/del/:id). Triggers the
        on<Proto>Changed hook -> config regen + daemon restart, so call while no
        client is connected to it."""
        self._post(f"/panel/api/inbounds/del/{inbound_id}", {})

    # ---- traffic + bulk (E2E test support) -----------------------------
    def get_client_traffics(self, email: str) -> dict:
        """Per-client counted traffic row: {up, down, total, enable, expiryTime,…}
        (bytes). Empty dict if the client has no traffic row yet."""
        return self._get(f"/panel/api/inbounds/getClientTraffics/{email}").get("obj", {}) or {}

    def reset_client_traffic(self, inbound_id: int, email: str):
        """Zero a client's counted up/down (also re-enables it). NOTE the handler
        also fires the on<Proto>Changed hooks -> VPN daemons restart, so call this
        while the client is DISCONNECTED."""
        self._post(f"/panel/api/inbounds/{inbound_id}/resetClientTraffic/{email}", {})

    def set_client_total(self, inbound_id: int, email: str, total_bytes: int):
        """Set one client's traffic limit (totalGB, in BYTES) + ensure enabled.
        Uses the updateClient endpoint (NOT a whole-inbound update) so the panel
        runs UpdateClientStat and syncs client_traffics.total — the enforcement
        table the auto-disable check reads. Restarts the daemon, so call while
        disconnected."""
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        target = None
        for c in settings.get("clients", []):
            if c.get("email") == email:
                target = dict(c)
                break
        if target is None:
            raise PanelError(f"client {email} not found on inbound {inbound_id}")
        target["totalGB"] = int(total_bytes)
        target["enable"] = True
        proto = ib.get("protocol", "")
        # UpdateInboundClient matches clientId by the protocol's identity field
        # (clientIdentityKey in web/service/inbound.go); see client_identity above.
        client_id = client_identity(proto, target)
        self._post(f"/panel/api/inbounds/updateClient/{client_id}", {
            "id": str(inbound_id),
            "remark": ib.get("remark", ""),
            "enable": "true",
            "listen": ib.get("listen", "") or "",
            "port": str(ib.get("port", 0)),
            "protocol": proto,
            "settings": json.dumps({"clients": [target]}),
            "streamSettings": "{}",
            "sniffing": "{}",
        })

    def set_mtproto_modes(self, inbound_id: int, email: str, modes) -> dict:
        """Flip one mtproto account's connection modes via updateClient, exactly as
        the UI's client modal does, and return the client JSON as posted.

        This is a CLIENT-only change, so the panel rewrites config.toml and lets
        telemt hot-reload it rather than restarting: live connections on the other
        accounts survive. That makes it the one path that proves the toggles reach
        the running daemon, which is not the same claim as "the config file is
        right". `modes` is any iterable of classic/secure/tls.
        """
        want = set(modes)
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        target = None
        for c in settings.get("clients", []):
            if c.get("email") == email:
                target = dict(c)
                break
        if target is None:
            raise PanelError(f"client {email} not found on inbound {inbound_id}")
        target["modeClassic"] = "classic" in want
        target["modeSecure"] = "secure" in want
        target["modeTls"] = "tls" in want
        # Identity is the email; the panel mirrors it into id (the wg-c model), so
        # either works as the clientId. Send what the UI sends.
        client_id = target.get("id", "") or target.get("email", "")
        self._post(f"/panel/api/inbounds/updateClient/{client_id}", {
            "id": str(inbound_id),
            "remark": ib.get("remark", ""),
            "enable": "true",
            "listen": ib.get("listen", "") or "",
            "port": str(ib.get("port", 0)),
            "protocol": ib.get("protocol", ""),
            "settings": json.dumps({"clients": [target]}),
            "streamSettings": "{}",
            "sniffing": "{}",
        })
        return target

    def set_mtproto_adtag(self, inbound_id: int, email: str, tag: str) -> dict:
        """Set (tag non-empty) or clear (tag "") one mtproto account's Ad Tag via
        updateClient, exactly as the UI's client modal does.

        The tag MUST be exactly 32 hex chars: telemt rejects any other length
        ("access.user_ad_tags[..] must be exactly 32 hex characters") and then simply
        runs without it, which would make an adtag test pass for the wrong reason.

        Turning the FIRST tag on an inbound on/off is not a hot-reloadable change:
        it flips telemt's use_middle_proxy, which needs a socket re-bind, and telemt's
        hot-reload path skips those fields with a warning. Callers must restart_core
        ("mtproto") after this, unlike set_mtproto_modes.
        """
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        target = None
        for c in settings.get("clients", []):
            if c.get("email") == email:
                target = dict(c)
                break
        if target is None:
            raise PanelError(f"client {email} not found on inbound {inbound_id}")
        target["adtagEnable"] = bool(tag)
        target["adtag"] = tag
        client_id = target.get("id", "") or target.get("email", "")
        self._post(f"/panel/api/inbounds/updateClient/{client_id}", {
            "id": str(inbound_id),
            "remark": ib.get("remark", ""),
            "enable": "true",
            "listen": ib.get("listen", "") or "",
            "port": str(ib.get("port", 0)),
            "protocol": ib.get("protocol", ""),
            "settings": json.dumps({"clients": [target]}),
            "streamSettings": "{}",
            "sniffing": "{}",
        })
        return target

    def bulk_update_clients(self, payload: dict) -> dict:
        """POST the bulk client op (form field data=JSON string, matching the panel
        axios convention). Returns {applied, skipped}."""
        return self._post("/panel/api/inbounds/bulkUpdateClients",
                          {"data": json.dumps(payload)}).get("obj", {}) or {}

    def get_client(self, inbound_id: int, email: str) -> dict:
        """Read one client's settings dict (totalGB/expiryTime/enable/…) by email."""
        ib = self.get_inbound(inbound_id)
        settings = json.loads(ib.get("settings") or "{}")
        for c in settings.get("clients", []):
            if c.get("email") == email:
                return c
        return {}

    def generate_openvpn_certs(self) -> dict:
        """Returns {caCert,caKey,serverCert,serverKey,tlsCrypt}."""
        return self._post("/panel/api/inbounds/generate-openvpn-certs", {}).get("obj", {})

    def generate_ocserv_cert(self) -> dict:
        """Returns {certificate, key} — a self-signed server cert for OpenConnect."""
        return self._post("/panel/api/inbounds/generate-ocserv-cert", {}).get("obj", {})

    def generate_ikev2_cert(self) -> dict:
        """Returns {certificate, key, caCert} — a self-signed server cert + its CA for
        IKEv2 (strongSwan). The server presents `certificate`; the CLIENT must TRUST
        `caCert` (load it into swanctl's x509ca dir) to validate the server. With an
        empty serverAddr the leaf SAN = the server's detected IP, so the client's
        `remote { id = <server_ip> }` matches."""
        return self._post("/panel/api/inbounds/generate-ikev2-cert", {}).get("obj", {})

    def wgc_configs(self, inbound_id: int, email: str) -> list:
        """Fetch a WireGuard (C) account's per-device client configs. Returns a list
        of {deviceIndex, ip, publicKey, config} (one per device = the account's User
        Limit K). The panel mints any missing server/device keypairs on this call, so
        it is safe to call right after add_inbound."""
        from urllib.parse import quote
        return self._get(
            f"/panel/api/inbounds/{inbound_id}/wgc-configs?email={quote(email)}"
        ).get("obj", []) or []

    def awg_configs(self, inbound_id: int, email: str) -> list:
        """Fetch an AmneziaWG account's per-device client configs. Same shape as
        wgc_configs (a list of {deviceIndex, ip, publicKey, config}, one per device =
        the account's User Limit K), the config text additionally carrying the AmneziaWG
        obfuscation params. The panel mints any missing server/device keypairs on this
        call, so it is safe to call right after add_inbound."""
        from urllib.parse import quote
        return self._get(
            f"/panel/api/inbounds/{inbound_id}/awg-configs?email={quote(email)}"
        ).get("obj", []) or []

    def gre_configs(self, inbound_id: int, email: str) -> list:
        """Fetch a GRE account's per-peer router setup. Returns a list of
        {peerIndex, peerIp, dynamic, serverIp, innerIp, gatewayIp, mode, ipsecPsk,
        fouPort, config} (one per peer slot = the account's User Limit K). Unlike the
        wg endpoints nothing is minted here: GRE has no key material, so this is a pure
        render of the addresses the panel already assigned."""
        from urllib.parse import quote
        return self._get(
            f"/panel/api/inbounds/{inbound_id}/gre-configs?email={quote(email)}"
        ).get("obj", []) or []

    def patch_gre_settings(self, inbound_id: int, **changes) -> dict:
        """Flip GRE inbound switches (ipsecEnable / allowRaw / fouEnable / ...) in place,
        preserving everything else in the settings blob (clients and their peer slots
        above all: update_inbound rewrites the whole settings JSON, so a partial body
        would drop every account)."""
        cur = self.get_inbound(inbound_id) or {}
        settings = json.loads(cur.get("settings") or "{}")
        settings.update(changes)
        return self.update_inbound(inbound_id, cur.get("remark") or "test-gre",
                                   int(cur.get("port") or 47), "gre", settings,
                                   listen=cur.get("listen") or "")

    def set_gre_peer(self, inbound_id: int, email: str, peer_index: int,
                     peer_ip: str) -> dict:
        """Set one account's peer-slot public IP. Blank means 'dynamic', which is a
        supported state, not an empty field: that peer is then served by the shared
        catch-all tunnel with a learned reverse path."""
        cur = self.get_inbound(inbound_id) or {}
        settings = json.loads(cur.get("settings") or "{}")
        clients = settings.get("clients") or []
        found = False
        for c in clients:
            if c.get("email") != email:
                continue
            peers = c.get("peers")
            if not isinstance(peers, list):
                peers = []
            while len(peers) <= peer_index:
                peers.append({})
            peers[peer_index] = dict(peers[peer_index] or {})
            peers[peer_index]["peerIp"] = peer_ip
            c["peers"] = peers
            found = True
            break
        if not found:
            raise AssertionError(f"account {email} not found on gre inbound {inbound_id}")
        settings["clients"] = clients
        return self.update_inbound(inbound_id, cur.get("remark") or "test-gre",
                                   int(cur.get("port") or 47), "gre", settings,
                                   listen=cur.get("listen") or "")

    def download_ovpn(self, inbound_id: int, proto: str) -> str:
        """proto in {udp,tcp}. Returns raw .ovpn text."""
        r = self.s.get(self._url(f"/panel/api/inbounds/{inbound_id}/ovpn/{proto}"),
                       timeout=self.timeout)
        if r.status_code != 200 or "openvpn" not in r.headers.get(
                "Content-Type", "") and "client" not in r.text[:20].lower():
            # controller returns the file directly; on error it returns the JSON envelope
            try:
                body = r.json()
                raise PanelError(f"ovpn export failed: {body.get('msg')}")
            except ValueError:
                pass
        return r.text

    # ---- xray outbound + routing ---------------------------------------
    def get_xray_template(self) -> dict:
        """Return the parsed Xray config template (dict with outbounds, routing…)."""
        body = self._post("/panel/xray/", {})
        obj = body.get("obj")
        # obj is a JSON string: {"xraySetting":<obj>, "inboundTags":..., ...}
        if isinstance(obj, str):
            obj = json.loads(obj)
        setting = obj.get("xraySetting")
        if isinstance(setting, str):
            setting = json.loads(setting)
        return setting

    def update_xray_template(self, template: dict):
        self._post("/panel/xray/update", {
            "xraySetting": json.dumps(template),
        })

    def get_config_json(self) -> dict:
        """The fully merged runtime Xray config (routing rules already translated
        from user-email to source-IP). Used to assert the translation happened."""
        body = self._get("/panel/api/server/getConfigJson")
        obj = body.get("obj")
        if isinstance(obj, str):
            obj = json.loads(obj)
        return obj

    # ---- Cloudflare warp-cli SOCKS5 (E2E test support) -----------------
    # POST /panel/xray/warpsocks/:action. install/uninstall kick off a
    # background run and return the initial state; the caller then polls
    # "state" for the live log. The install feeds the SOCKS5 port via the
    # `port` form field (the backend forwards it as WARP_SOCKS_PORT).
    def warpsocks_installed(self) -> bool:
        return bool(self._post("/panel/xray/warpsocks/installed", {})
                    .get("obj", {}).get("installed", False))

    def warpsocks_start(self, action: str, port: int = 0) -> dict:
        """action in {install, uninstall}. Returns the initial run state dict
        {running,done,success,action,log}."""
        data = {"port": str(port)} if action == "install" else {}
        return self._post(f"/panel/xray/warpsocks/{action}", data).get("obj", {}) or {}

    def warpsocks_state(self) -> dict:
        """Snapshot of the current/most-recent warp-cli run: {running,done,
        success,action,log}."""
        return self._post("/panel/xray/warpsocks/state", {}).get("obj", {}) or {}

    # ---- db backup / restore (E2E test support) ------------------------
    def download_db(self) -> bytes:
        """GET /panel/api/server/getDb -> the raw SQLite file bytes (an
        octet-stream attachment, NOT the JSON envelope). Asserts the SQLite magic
        so an HTML/JSON error page can't masquerade as a valid backup."""
        r = self.s.get(self._url("/panel/api/server/getDb"), timeout=self.timeout)
        if r.status_code != 200:
            raise PanelError(f"getDb -> HTTP {r.status_code}: {r.text[:200]}")
        if not r.content.startswith(b"SQLite format 3\x00"):
            raise PanelError(
                f"getDb did not return a SQLite db (first bytes: {r.content[:16]!r})")
        return r.content

    def import_db(self, db_bytes: bytes) -> dict:
        """POST /panel/api/server/importDB (multipart, form field name 'db').
        Replaces the live DB (InitDB + MigrateDB in-process) and restarts Xray;
        returns the JSON envelope. Re-login afterwards — the swap may drop the
        server-side session."""
        r = self.s.post(
            self._url("/panel/api/server/importDB"),
            files={"db": ("x-ui.db", db_bytes, "application/octet-stream")},
            timeout=self.timeout,
        )
        return self._envelope(r, "/panel/api/server/importDB")

    # ---- subscription (E2E) --------------------------------------------
    def get_all_settings(self) -> dict:
        """POST /panel/setting/all -> the full AllSetting object (every setting except
        xrayTemplateConfig). The panel serves this as POST, not GET."""
        return self._post("/panel/setting/all", {}).get("obj", {}) or {}

    def update_all_settings(self, settings: dict) -> dict:
        """POST the complete AllSetting back. updateAllSetting binds a fresh struct and
        saves every field it carries, so a COMPLETE dict must be passed (get it via
        get_all_settings, mutate, hand back). Values are stringified for form binding;
        Go's ParseBool accepts 'true'/'false'."""
        body = {}
        for k, v in settings.items():
            if isinstance(v, bool):
                body[k] = "true" if v else "false"
            elif v is None:
                body[k] = ""
            else:
                body[k] = str(v)
        return self._post("/panel/setting/update", body)

    def enable_subscription(self) -> dict:
        """Turn the subscription server on (raw + JSON + Clash), plaintext (no base64)
        so the raw sub is greppable. Returns the merged settings (carries subPort +
        subPath/subJsonPath/subClashPath). The sub server only binds on a panel restart,
        so the caller must restart_panel_service() + wait_up() + login() after."""
        s = self.get_all_settings()
        s["subEnable"] = True
        s["subJsonEnable"] = True
        s["subClashEnable"] = True
        s["subShowInfo"] = True
        s["subEncrypt"] = False
        self.update_all_settings(s)
        return s

    def restart_panel_service(self):
        """POST /panel/setting/restartPanel — SIGHUPs the panel, which re-creates the
        sub server with the new subEnable. Caller must wait_up + login afterwards."""
        return self._post("/panel/setting/restartPanel", {})

    def set_client_subscription(self, inbound_id: int, sub_id: str,
                                total_bytes: int, expiry_ms: int) -> str:
        """Give an inbound's FIRST client a subId + quota + expiry so it groups into a
        subscription with real stats. Uses the updateClient endpoint (NOT a whole-inbound
        update) so the panel runs UpdateClientStat and syncs client_traffics.total/expiry
        — the table GetSubs reads for the Subscription-Userinfo header; a whole-inbound
        update leaves those 0. Preserves the client's protocol-specific fields. Returns
        the client email."""
        ib = self.get_inbound(inbound_id) or {}
        settings = json.loads(ib.get("settings") or "{}")
        clients = settings.get("clients") or []
        if not clients:
            raise PanelError(f"inbound {inbound_id} has no clients")
        target = dict(clients[0])
        target["subId"] = sub_id
        target["totalGB"] = int(total_bytes)
        target["expiryTime"] = int(expiry_ms)
        target["enable"] = True
        proto = ib.get("protocol", "")
        # clientId key per protocol (clientIdentityKey in web/service/inbound.go), same
        # mapping as set_client_total, including anytls/naive, which are keyed on
        # the password because neither carries a uuid.
        if proto in ("l2tp", "pptp", "openvpn", "trojan",
                     "openconnect", "sstp", "ikev2", "anytls", "naive"):
            client_id = target.get("password", "")
        elif proto == "shadowsocks":
            client_id = target.get("email", "")
        else:
            client_id = target.get("id", "") or target.get("email", "")
        self._post(f"/panel/api/inbounds/updateClient/{client_id}", {
            "id": str(inbound_id),
            "remark": ib.get("remark", ""),
            "enable": "true",
            "listen": ib.get("listen", "") or "",
            "port": str(ib.get("port", 0)),
            "protocol": proto,
            "settings": json.dumps({"clients": [target]}),
            "streamSettings": "{}",
            "sniffing": "{}",
        })
        return target.get("email", "")

    def fetch_sub(self, server_ip: str, sub_port: int, path: str, sub_id: str):
        """GET a subscription off the dedicated sub server (public, no auth). Returns
        (status_code, text, headers). path is subPath / subJsonPath / subClashPath."""
        url = f"http://{server_ip}:{sub_port}{path}{sub_id}"
        r = requests.get(url, timeout=self.timeout)
        return r.status_code, r.text, r.headers
