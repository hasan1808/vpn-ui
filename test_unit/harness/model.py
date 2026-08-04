"""Result model shared across the harness.

A run produces one JobResult per server distro. Each JobResult holds an ordered
list of Phases; each Phase holds SubTests. Everything serialises to plain dicts
for the JSON report; the HTML report renders the same structure.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"   # deliberately not run (e.g. dependency of a failed step)
    NA = "na"       # not applicable / external dependency unavailable
    ERROR = "error" # harness/infra blew up (not a product failure)


def worst(statuses) -> Status:
    """Roll a collection of statuses up to a single verdict.

    Precedence: ERROR > FAIL > PASS > NA > SKIP. Crucially PASS outranks NA/SKIP,
    so an otherwise-green phase with one inconclusive check (e.g. a flaky
    external dns-leak service = NA) still rolls up to PASS rather than being
    dragged down. NA/SKIP only surface when nothing actually passed."""
    seen = {Status(s) for s in statuses}
    if not seen:
        return Status.SKIP
    for level in (Status.ERROR, Status.FAIL, Status.PASS, Status.NA, Status.SKIP):
        if level in seen:
            return level
    return Status.SKIP


@dataclass
class SubTest:
    name: str
    status: Status = Status.SKIP
    detail: str = ""          # one-line human summary
    log: str = ""             # full captured output for the drilldown
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Phase:
    name: str
    subtests: list = field(default_factory=list)

    def add(self, sub: SubTest) -> SubTest:
        self.subtests.append(sub)
        return sub

    @property
    def status(self) -> Status:
        return worst(s.status for s in self.subtests)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "subtests": [s.to_dict() for s in self.subtests],
        }


@dataclass
class JobResult:
    distro: str
    image: str
    phases: list = field(default_factory=list)
    started_at: str = ""      # ISO8601, stamped by orchestrator
    finished_at: str = ""
    server_ip: str = ""
    notes: str = ""           # infra-level message (e.g. "image not found -> skipped")

    def phase(self, name: str) -> Phase:
        """Get-or-create a phase by name, preserving insertion order."""
        for p in self.phases:
            if p.name == name:
                return p
        p = Phase(name)
        self.phases.append(p)
        return p

    @property
    def status(self) -> Status:
        return worst(p.status for p in self.phases)

    def to_dict(self) -> dict:
        return {
            "distro": self.distro,
            "image": self.image,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "server_ip": self.server_ip,
            "notes": self.notes,
            "phases": [p.to_dict() for p in self.phases],
        }


# Canonical phase names (kept stable so the report columns line up).
PHASE_CORE = "core-init"
PHASE_SETUP = "server-setup"
PHASE_OPENVPN = "openvpn"
PHASE_L2TP = "l2tp"
PHASE_PPTP = "pptp"
PHASE_OPENCONNECT = "openconnect"
PHASE_SSTP = "sstp"
PHASE_IKEV2 = "ikev2"                        # selection alias -> the per-mode phases below
PHASE_IKEV2_EAPMSCHAP = "ikev2-eap-mschapv2"
PHASE_IKEV2_PSK = "ikev2-psk"
PHASE_IKEV2_EAPTLS = "ikev2-eap-tls"
# Each IKEv2 auth mode is its own phase/column and runs the full applicable suite
# (eap-mschapv2 = the RADIUS path + 2-account tests; psk/eap-tls = the single-account
# rbridge-sweep path). Order = the order they run in.
IKEV2_MODE_PHASES = [PHASE_IKEV2_EAPMSCHAP, PHASE_IKEV2_PSK, PHASE_IKEV2_EAPTLS]
IKEV2_PHASE_BY_MODE = {"eap-mschapv2": PHASE_IKEV2_EAPMSCHAP,
                       "psk": PHASE_IKEV2_PSK, "eap-tls": PHASE_IKEV2_EAPTLS}
PHASE_WGC = "wg-c"                        # WireGuard (C) — kernel wireguard via wgctrl
PHASE_AWG = "awg"                         # AmneziaWG — obfuscated kernel wireguard (same gateway model as wg-c)
PHASE_GRE = "gre"                         # GRE — kernel ip_gre site-to-site (router peers; raw / IPsec / FOU)
PHASE_MTPROTO = "mtproto"                 # selection alias -> the per-mode phases below
PHASE_MTPROTO_CLASSIC = "mtproto-classic"
PHASE_MTPROTO_SECURE = "mtproto-secure"
PHASE_MTPROTO_TLS = "mtproto-tls"
# Each MTProto connection mode is its own phase/column. Unlike IKEv2's auth modes
# (which are mutually exclusive per inbound), all three MTProto modes are served by
# ONE inbound simultaneously: the client picks by its secret's prefix. So the modes
# differ only in how the client dials, and they share a single inbound.
MTPROTO_MODE_PHASES = [PHASE_MTPROTO_CLASSIC, PHASE_MTPROTO_SECURE, PHASE_MTPROTO_TLS]
MTPROTO_PHASE_BY_MODE = {"classic": PHASE_MTPROTO_CLASSIC,
                         "secure": PHASE_MTPROTO_SECURE, "tls": PHASE_MTPROTO_TLS}
# Editing an account's modes, which the three phases above cannot cover: they read a
# mode set that was fixed at inbound creation. telemt takes modes from TWO places -
# [general.modes] (process-wide, the UNION over accounts) and [access.user_modes]
# (per account), and the union only MOVES when an edit adds a mode no other account
# had. Miss the hot-reload on either and the toggle silently does nothing until the
# next restart, which is exactly what a user sees as "the backend ignores my toggle".
PHASE_MTPROTO_TOGGLE = "mtproto-toggle"
# Quota -> auto-disable -> the account can no longer relay. The per-mode `usage` subtest
# only proves bytes are COUNTED; nothing proved they are ENFORCED, and mtproto's
# enforcement path is its own (no RADIUS, no nft): the panel re-renders
# [access.user_enabled] and telemt's config watcher cancels the account's live sessions.
# Deliberately KiB-scale: the prober's ceiling is ~1.6 KiB/s per connection because each
# req_pq is a full round-trip to a DC, so an MB-scale quota can never be driven over.
PHASE_MTPROTO_TERMINATION = "mtproto-termination"
# Ad Tag, and the XOR it forces. A tagged account needs telemt's middle-proxy path, whose
# RPC session key is derived from the proxy's own egress IP AND port, so ANY re-originating
# proxy (Xray socks included) breaks the handshake. The panel therefore drops the whole
# inbound's Xray socks inbound the moment any account carries a tag. That trade is the
# product rule worth testing; whether Telegram then CREDITS the tag is account-gated and
# out of scope. Note the tag rides the proxy->Telegram leg (RPC_PROXY_REQ), so the client
# handshake is byte-identical either way: every assertion here is server-side.
PHASE_MTPROTO_ADTAG = "mtproto-adtag"
# SSH (10th protocol): an in-binary Go x/crypto/ssh RELAY. The client turns it into a
# full system tunnel with `ssh -D` (dynamic SOCKS) + badvpn-tun2socks (+ udpgw for UDP),
# so PHASE_SSH runs the SAME shared suite as the tunnel protocols MINUS client-to-client
# and cross-inbound (a relay has no client tunnel address to ping between). PHASE_SSH_UDP
# is a dedicated phase proving UDP survives the udpgw path end-to-end (functional +
# billed to the account). `--tests ssh` selects both (see orchestrator.main).
PHASE_SSH = "ssh"
PHASE_SSH_UDP = "ssh-udp"
# Xray-NATIVE proxy protocols (11th-13th). Unlike every phase above them these are
# served by the xray core itself, not by a bundled daemon or an in-binary Go server:
# the panel writes them straight into the xray config as inbounds, so their data path,
# their per-account accounting and their user matching are the core's own. The client
# is xray as well (a local socks inbound + the matching outbound) plus
# badvpn-tun2socks on tun0, exactly the system-tunnel trick clients/ssh.py uses, so
# they run the SAME shared suite MINUS everything that needs a client tunnel address.
PHASE_ANYTLS = "anytls"
PHASE_TUIC = "tuic"
PHASE_NAIVE = "naive"
# ONE account across an inbound of every account-bearing protocol: the
# accounts/membership layer driven end to end. See harness/multi_inbound.py.
PHASE_MULTI = "multi-inbound"
PHASE_BULK = "bulk-ops"
PHASE_BACKUP = "backup-restore"
PHASE_SUBSCRIPTION = "subscription"      # sub links/JSON/Clash + stats, every protocol
PHASE_WARP = "warp-socks"
PHASE_RANDOM = "random-cfg"
PHASE_SYSTEMD = "systemd"
PHASE_UNINSTALL = "uninstall"

ALL_PHASES = [PHASE_CORE, PHASE_SETUP, PHASE_OPENVPN, PHASE_L2TP, PHASE_PPTP,
              PHASE_OPENCONNECT, PHASE_SSTP,
              PHASE_IKEV2_EAPMSCHAP, PHASE_IKEV2_PSK, PHASE_IKEV2_EAPTLS,
              PHASE_WGC,
              PHASE_AWG,
              PHASE_GRE,
              PHASE_MTPROTO_CLASSIC, PHASE_MTPROTO_SECURE, PHASE_MTPROTO_TLS,
              PHASE_MTPROTO_TOGGLE, PHASE_MTPROTO_TERMINATION, PHASE_MTPROTO_ADTAG,
              PHASE_SSH, PHASE_SSH_UDP,
              PHASE_ANYTLS, PHASE_TUIC, PHASE_NAIVE,
              PHASE_MULTI,
              PHASE_BULK, PHASE_BACKUP, PHASE_SUBSCRIPTION,
              PHASE_WARP, PHASE_RANDOM, PHASE_SYSTEMD, PHASE_UNINSTALL]
