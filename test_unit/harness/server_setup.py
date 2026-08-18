"""Server-setup phase: build one inbound per protocol (each with 2 accounts),
add two email-based source-IP routing rules against the built-in outbounds
(A-accounts -> `direct`/freedom, B-accounts -> `blocked`/blackhole), and assert
the panel translated the blackhole rule to a per-client source-IP rule.

Topology (chosen so no port/tag collisions and both client VMs are reused):
  - one inbound per protocol, clientToClient + crossInbound both enabled
  - account A on client-VM-A, account B on client-VM-B
  - client-to-client  = A and B on the SAME protocol inbound
  - cross-inbound     = A on protocol X, B on protocol Y (cross-protocol; the
    nftables gate is IP/inbound-level, so this exercises the same code path)

Tunnel IPs are deterministic (radius.go computeVpnClientIP / vpnrange.go):
  IP = 10.<base>.<inboundId>.<2 + clientIndex>, base: l2tp=0 pptp=1 ovpn-udp=2 ovpn-tcp=3
"""
from __future__ import annotations

import base64
import binascii
import hashlib

from dataclasses import dataclass, field

from . import ikev2_certs
from .clients.xraytun import tuic_uuid
from .model import JobResult, SubTest, Status, PHASE_SETUP
from .panel import Panel

# protocol base octet for the 10.<base>.<id>.<host> tunnel address
BASE = {"l2tp": 0, "pptp": 1, "ovpn-udp": 2, "ovpn-tcp": 3, "openconnect": 4,
        "sstp": 5, "ikev2": 6, "wg-c": 7, "awg": 8, "gre": 9}

PSK = "TestPSK-9182"  # L2TP/IPsec pre-shared key
IKEV2_PSK = "TestIkev2PSK-7f3a91"  # IKEv2 psk-mode shared key (single-account inbound)
GRE_PSK = "TestGrePSK-4c81de"  # GRE-over-IPsec (ESP transport) pre-shared key
# Distinct IKE server identity (IDr) for the eap-tls inbound. The always-present primary
# eap-mschapv2 inbound presents id=server_ip; two EAP conns with the SAME server id on the
# ONE shared charon can't be disambiguated (an EAP initiator looks identical until the
# method is negotiated, so charon picks eap-mschapv2 first and the eap-tls client rejects
# the MSCHAPv2 offer). Giving eap-tls its own IDr makes charon route to it by identity.
IKEV2_EAPTLS_ID = "ikev2-eaptls.vpn"

# User Limit (devices per account). All three protocols run at K=2 so the User
# Limit Strategy test can drive a 3rd device past the cap (needs the 3rd client
# VM). K=2 also keeps the per-account block allocator + source-IP routing on the
# hot path for every protocol.
L2TP_USER_LIMIT = 2
OVPN_USER_LIMIT = 2
PPTP_USER_LIMIT = 2
OC_USER_LIMIT = 2
SSTP_USER_LIMIT = 2
IKEV2_USER_LIMIT = 2
# SSH relay: "device" = distinct client source IP per account, enforced in the in-binary
# Go SSH server. K=2 keeps the same User-Limit / strategy / multi-user-total / termination
# suite the tunnel protocols run (the 3rd client VM drives the past-cap strategy test).
SSH_USER_LIMIT = 2
# The in-binary SSH server binds this TCP port on 0.0.0.0. 2222 avoids the VM's own sshd
# on 22. Stored in the Inbound.udp_port field (a port label, so multi-inbound's per-proto
# `.udp_port` reads work) even though the SSH listener is TCP.
SSH_PORT = 2222

# ---- Xray-native proxy protocols (anytls / tuic / naive) ---------------------
# The odd ones out among the recent additions: no daemon, no RADIUS, no tunnel and no
# 10.x block; xray itself terminates them, matches the account and dispatches. So they
# have NO BASE entry (client_ip() raises for them), they are NOT in corecatalog (an
# Xray-native protocol maps to no core), and their per-client routing is by the account
# EMAIL carried on the session, which the panel's routing rules match directly without
# any email->source-IP translation.
#
# Ports are picked clear of every other inbound in a full run (443/500/1194/1443/1701/
# 1723/2222/4443/4500/8443 primaries, the SECOND_PORTS block below, and the panel's own
# 2083/2097). tuic listens on UDP (QUIC); anytls and naive on TCP.
ANYTLS_PORT = 8447
TUIC_PORT = 8448
NAIVE_PORT = 8449
# NOTE the inbound pins NO serverName: it accepts whatever SNI the client sends (which
# clients/xraytun.py's Spec.sni supplies) and presents a self-signed certificate the
# client is told to accept, so there is no name to keep in step on this side.
# naive serves BOTH carriers on the primary inbound (h2 over TLS/TCP and h3 over QUIC/
# UDP on the same port number). The client dials h2; serving h3 as well means a broken
# h3 listener still shows up here as a failed inbound rather than going unnoticed.
NAIVE_NETWORK = "tcp,udp"
# AnyTLS padding scheme: left EMPTY on purpose so the inbound takes the library default.
# A custom scheme is itself a fingerprint, and the default is the interoperable one.
ANYTLS_PADDING_SCHEME: list = []

# WireGuard (C): gateway model. ONE keypair per account; the User Limit sizes the account's
# aligned IP block (rounded up to a power of two), and the single config's Address is that
# whole block (e.g. 6 -> a /29 of 8 addresses) which a router hands out to its LAN. 6 -> /29.
# Per-device tests (user-limit 2nd device / multi-user-total / strategy) are Not Applicable
# (one keypair can't split into distinct simultaneous device IPs — the /29 IS the block).
WGC_USER_LIMIT = 6
# AmneziaWG = the SAME gateway model as wg-c (one keypair per account, block sized by the
# User Limit -> a /29), just obfuscated. So it uses the identical per-account block sizing.
AWG_USER_LIMIT = 6
# GRE: K = peer ROUTERS per account, sized like the wg family (aligned power-of-two
# block). 2 is enough to prove the block allocator and leaves the second slot free.
GRE_USER_LIMIT = 2

# ---- MTProto Proxy -----------------------------------------------------------
# 8443, not 443: the panel itself may hold 443, and MTProto needs a real TCP port
# of its own (there is no tunnel to share). FakeTLS plausibility does not matter to
# the prober, which checks the ServerHello HMAC rather than a browser's opinion.
MTPROTO_PORT = 8443
MTPROTO_TLS_DOMAIN = "www.google.com"
# 3 distinct client IPs per account. telemt enforces this itself (user_max_unique_ips)
# by refusing the excess device: there is no evict-oldest strategy to choose.
MTPROTO_USER_LIMIT = 3
# Fixed per-account secrets so the harness can build the client-facing shapes without
# reading them back. Real deployments have the panel mint these.
_MT_SECRET = ["00112233445566778899aabbccddeeff",
              "ffeeddccbbaa99887766554433221100"]


def _mt_client(acct: Account, idx: int) -> dict:
    """An mtproto client as the panel API expects it.

    Identity is the EMAIL (there is no username: the wg-c model); the credential is
    `secret`. That plus the external-proxy list is ALL an account owns: the connection
    modes, the FakeTLS domain, the ad tag and the device cap belong to the inbound
    (_mt_inbound_settings), because telemt applies each of them process-wide.

    `id` is still sent because the panel's shared client plumbing is id-keyed; it
    mirrors the email exactly, the way wg-c does it.
    """
    return {"id": acct.email, "email": acct.email, "secret": _MT_SECRET[idx],
            "enable": True,
            "externalProxy": [],
            "expiryTime": 0, "totalGB": 0, "limitIp": 0,
            "tgId": "", "subId": "", "comment": "", "reset": 0}


def _mt_inbound_settings(clients, modes=("classic", "secure", "tls")) -> dict:
    """The mtproto inbound's own settings: which transports the listener accepts, the
    domain its FakeTLS emulation models, the ad tag, and the per-account device cap."""
    return {
        "modeClassic": "classic" in modes,
        "modeSecure": "secure" in modes,
        "modeTls": "tls" in modes,
        "tlsDomain": MTPROTO_TLS_DOMAIN,
        "adtagEnable": False,
        "adtag": "",
        "userLimit": MTPROTO_USER_LIMIT,
        "clients": clients,
    }


def _mt_secret_shapes(base: str) -> dict:
    """The same 16-byte secret in each client-facing shape. The prefix is what tells
    the client (and telemt) which transport to speak:
      classic -> bare, secure -> "dd"+secret, tls -> "ee"+secret+hex(domain)."""
    return {
        "classic": base,
        "secure": "dd" + base,
        "tls": "ee" + base + MTPROTO_TLS_DOMAIN.encode().hex(),
    }

# Ports for the SECOND same-protocol inbound (protocols.py multi-inbound test).
# Distinct from the primary ports (openvpn udp 1194 / tcp 1443, l2tp 1701, pptp
# 1723) and from each other so the panel's port-uniqueness check passes. NOTE:
# xl2tpd/pptpd each bind ONE fixed port (1701/1723) and serve every inbound —
# differentiated by account -> RADIUS -> IP range — so for l2tp/pptp this port is
# only a unique label; only openvpn actually listens on its own per-inbound port.
SECOND_PORTS = {
    "openvpn":     {"udp": 1195, "tcp": 1444},
    "l2tp":        {"udp": 1799},
    "pptp":        {"udp": 1798},
    "openconnect": {"udp": 4444},
    # 8444, not 8443: MTProto's primary listener holds 8443 (MTPROTO_PORT), so an
    # all-protocols run (both present) would fail the sstp 2nd-inbound create with
    # "Port already exists: 8443". A distinct TLS-ish port avoids the collision.
    "sstp":        {"udp": 8444},
    # IKEv2 shares ONE strongSwan charon bound to UDP 500/4500 for EVERY inbound, so
    # this port is only a unique DB label (like l2tp/pptp above); the 2nd inbound is
    # distinguished by its own /16-block accounts via RADIUS, not by a distinct port.
    "ikev2":       {"udp": 4500},
    # WireGuard listens on its OWN per-inbound UDP port (a kernel wgc<id> interface),
    # so this really binds a distinct listener (like openvpn/sstp, unlike l2tp/pptp).
    "wg-c":       {"udp": 51821},
    # AmneziaWG likewise binds its OWN per-inbound UDP port (a kernel awg<id> interface),
    # so this really binds a distinct listener (like wg-c).
    "awg":        {"udp": 51823},
    # The SSH server binds its OWN per-inbound TCP listener, so this 2nd inbound really
    # binds a distinct port (like openvpn/wg-c). Distinct from the primary 2222.
    "ssh":        {"udp": 2223},
    # GRE is IP protocol 47 and binds NO port at all, so this is only a unique DB label
    # (like l2tp/pptp/ikev2 above). A 2nd GRE inbound is distinguished purely by its own
    # /16 block, which is exactly what this test exercises.
    "gre":        {"udp": 48},
    # Xray-native: each inbound really is its OWN listener inside the one xray process
    # (a second listen socket, not a second daemon), so these bind for real, which is
    # the point of the multi-inbound test for them: two inbounds of one protocol must
    # coexist in a single core config.
    "anytls":     {"udp": 8457},
    "tuic":       {"udp": 8458},
    "naive":      {"udp": 8459},
}

# Nominal DB port labels for the EXTRA ikev2 auth-mode inbounds (psk / eap-tls).
# Like SECOND_PORTS["ikev2"], these are unique labels only — the one shared charon
# binds 500/4500 for every ikev2 inbound; each is distinguished by its own account
# block, not by a distinct listener. Distinct from every other inbound's port.
IKEV2_EXTRA_PORTS = {"psk": 4501, "eap-tls": 4502}
# Devices-per-account for the psk/eap-tls inbounds. K=2 so each mode runs the full
# User-Limit / strategy / multi-user-total / termination suite against the rbridge sweep,
# not just a connect smoke. The shared charon admits multiple SAs per identity (proven
# by the eap-mschapv2 K=2 test), so the 2 devices share the single account.
IKEV2_EXTRA_USER_LIMIT = 2


def _xray_stream(panel: Panel, network: str = "tcp", extra: dict | None = None) -> dict:
    """streamSettings for an Xray-native inbound: TLS carrying a throwaway self-signed
    certificate. `extra` merges in a per-transport settings block (naiveSettings).

    All three protocols need TLS (tuic's hub refuses to start without it, naive is
    HTTP/2 or /3 over TLS, and AnyTLS is named after it), and TLS for an Xray-native
    inbound lives in streamSettings rather than in the protocol's own settings, which
    is exactly why panel.add_inbound had to grow a `stream` argument.

    The cert comes from the panel's own generator (no openssl on the host, no material
    checked into the repo) and is NOT persisted anywhere: called with no inbound id,
    generate-ocserv-cert just mints a pair and returns it. The client sets
    allowInsecure, so a self-signed cert with no matching SAN is fine.

    ALPN is deliberately NOT pinned here: each protocol's own hub sets what it needs
    (tuic forces h3), and a value set here would fight it."""
    c = panel.generate_ocserv_cert() or {}
    stream = {
        "network": network,
        "security": "tls",
        "tlsSettings": {
            "certificates": [{
                "certificate": [c.get("certificate", "")],
                "key": [c.get("key", "")],
            }],
        },
    }
    stream.update(extra or {})
    return stream


def stream_cert_sha256(stream: dict) -> str:
    """SHA-256 of the DER form of the certificate an _xray_stream is carrying, hex.

    This is what a client has to pin now. Xray REMOVED "allowInsecure" outright: after
    2026-06-01 a config carrying it is refused with "The feature allowInsecure has been
    removed and migrated to pinnedPeerCertSha256", so every TLS client driver in this
    harness stopped being able to start on that date. Pinning is also strictly better
    here: it verifies the exact certificate the panel minted instead of accepting any,
    and it sets InsecureSkipVerify itself (tls/config.go:398), so a self-signed cert
    with no matching SAN still connects.

    Parsed by hand rather than with cryptography: a PEM body IS base64 of the DER, and
    the harness already avoids adding host-side dependencies for one hash."""
    try:
        pem = (((stream.get("tlsSettings") or {}).get("certificates") or [{}])[0]
               .get("certificate") or [""])[0]
    except (IndexError, AttributeError, TypeError):
        return ""
    body = "".join(ln.strip() for ln in (pem or "").splitlines()
                   if ln.strip() and not ln.startswith("-----"))
    if not body:
        return ""
    try:
        return hashlib.sha256(base64.b64decode(body)).hexdigest()
    except (ValueError, binascii.Error):
        return ""


def _tuic_client(a: Account) -> dict:
    """A TUIC client as the panel API expects it. Identity is `id` (a UUID) alongside
    the password, so the id is NOT the username here: it is derived from the email by
    the same helper the client driver uses, so the two ends can never drift."""
    return {"id": tuic_uuid(a.email), "password": a.password,
            "email": a.email, "enable": True}


def build_second_inbound(panel: Panel, proto: str) -> Inbound:
    """Create a SECOND inbound of `proto` on a distinct port + IP pool with its own
    single account (index 0, user_limit=1), for the multi-inbound-same-proto E2E
    test (protocols.py). Returns the Inbound. Raises on panel error (the caller
    treats an inability to create a 2nd same-proto inbound as a product FAIL).
    Reuses the exact settings shapes the primary inbounds are built with above."""
    ports = SECOND_PORTS[proto]
    acct = _acct(proto + "2", 0)   # distinct emails: ovpn2a@t / l2tp2a@t / pptp2a@t
    if proto == "openvpn":
        certs = panel.generate_openvpn_certs()
        settings = {
            "udpEnable": True, "tcpEnable": True,
            "tcpPort": ports["tcp"],
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "caCert": certs["caCert"], "caKey": certs["caKey"],
            "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
            "tlsCrypt": certs["tlsCrypt"],
            "cipherMode": "all",
            "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-openvpn-2", ports["udp"], "openvpn", settings)
        iid = inb["id"]
        return Inbound(
            protocol="openvpn", inbound_id=iid, udp_port=ports["udp"],
            tcp_port=ports["tcp"], accounts={"A": acct},
            ovpn_udp=panel.download_ovpn(iid, "udp"),
            ovpn_tcp=panel.download_ovpn(iid, "tcp"), user_limit=1)
    if proto == "l2tp":
        settings = {
            "ipsecEnable": True, "ipsecPsk": PSK, "allowRaw": True,
            "clientToClient": True, "crossInbound": True,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-l2tp-2", ports["udp"], "l2tp", settings)
        return Inbound(
            protocol="l2tp", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, psk=PSK, user_limit=1)
    if proto == "pptp":
        settings = {
            "clientToClient": True, "crossInbound": True,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-pptp-2", ports["udp"], "pptp", settings)
        return Inbound(
            protocol="pptp", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
    if proto == "openconnect":
        cert = panel.generate_ocserv_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-openconnect-2", ports["udp"], "openconnect", settings)
        return Inbound(
            protocol="openconnect", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
    if proto == "sstp":
        # accel-ppp listens on its OWN per-inbound port (like openvpn/ocserv, unlike
        # xl2tpd/pptpd), so this 2nd inbound really binds a distinct SSTP/TLS port.
        cert = panel.generate_ocserv_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-sstp-2", ports["udp"], "sstp", settings)
        return Inbound(
            protocol="sstp", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
    if proto == "ikev2":
        # The 2nd inbound is served by the SAME shared charon (bound to 500/4500); its
        # port is a nominal label. Its own generated cert/CA is captured so the client
        # can trust it (clients/ikev2.py accumulates every inbound's CA in x509ca/).
        cert = panel.generate_ikev2_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "authMode": "eap-mschapv2", "serverAddr": "",
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"], "caCert": cert["caCert"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-ikev2-2", ports["udp"], "ikev2", settings)
        return Inbound(
            protocol="ikev2", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1,
            ca_cert=cert.get("caCert", ""), server_addr="")
    if proto == "wg-c":
        # A distinct kernel wgc<id> interface on its own UDP port + 10.7 /24 pool,
        # single account (K=1). Keys are server-minted; fetch its device config too.
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "pskEnable": False,
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-wgc-2", ports["udp"], "wg-c", settings)
        second = Inbound(
            protocol="wg-c", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
        _fetch_wg_configs(panel, second)
        return second
    if proto == "awg":
        # A distinct kernel awg<id> interface on its own UDP port + 10.8 /24 pool,
        # single account (K=1). Keys + obfuscation params are server-minted; fetch its
        # device config too. Mirrors the wg-c case (same gateway model, awg backend).
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "pskEnable": False,
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-awg-2", ports["udp"], "awg", settings)
        second = Inbound(
            protocol="awg", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
        _fetch_awg_configs(panel, second)
        return second
    if proto == "gre":
        # A 2nd GRE inbound: its own 10.9 /24 block, single account (K=1). Its peer slot is
        # left BLANK on purpose, so this inbound's account is served by the shared catch-all
        # netdev. That is the interesting case for a multi-inbound test: two GRE inbounds
        # necessarily SHARE one catch-all (only one unkeyed device may bind a given local
        # address), so this asserts the shared device demultiplexes two inbounds' accounts
        # by inner address rather than clobbering one another.
        settings = {
            "mtu": 0, "ttl": 64,
            "ipsecEnable": False, "ipsecPsk": GRE_PSK, "allowRaw": True,
            "fouEnable": False, "fouPort": 15547,
            "clientToClient": True, "crossInbound": True,
            "userLimit": 1,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-gre-2", ports["udp"], "gre", settings)
        second = Inbound(
            protocol="gre", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, psk=GRE_PSK, user_limit=1)
        _fetch_gre_configs(panel, second)
        return second
    if proto == "ssh":
        # A distinct in-binary SSH listener on its own TCP port with a single account
        # (K=1). No addressing/certs: password auth only. externalProxy omitted (the
        # client dials the server IP:port directly). Strategy is pinned to reject so the
        # second inbound's K=1 cap is asserted deterministically (the default is accept).
        settings = {
            "userLimit": 1, "userLimitStrategy": "reject",
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-ssh-2", ports["udp"], "ssh", settings)
        return Inbound(
            protocol="ssh", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
    if proto in ("anytls", "tuic", "naive"):
        # A SECOND Xray-native inbound: a second listener inside the SAME xray process,
        # on its own port with its own account and its OWN self-signed certificate.
        # There is no IP pool to differ (these hand out no client address), so what the
        # multi-inbound test proves for them is that one core config carries two
        # inbounds of one protocol and both serve: a config the panel renders, so a
        # collision (duplicate tag, reused port, one settings block overwriting the
        # other) would take the whole core down, not just the second inbound.
        if proto == "anytls":
            settings = {"clients": [_dict_client(acct)],
                        "paddingScheme": ANYTLS_PADDING_SCHEME}
            stream = _xray_stream(panel, "tcp")
        elif proto == "tuic":
            settings = {"clients": [_tuic_client(acct)],
                        "congestionControl": "cubic", "authTimeout": 3,
                        "zeroRttHandshake": False, "heartbeat": 10, "udpTimeout": 60}
            stream = _xray_stream(panel, "tuic")
        else:
            # h2 only for the second naive inbound: the primary is the one that also
            # serves h3, so a second QUIC listener is not what this test is about.
            # settings.network and naiveSettings.network must agree (see the primary).
            settings = {"clients": [_dict_client(acct)], "network": "tcp",
                        "masquerade": {"type": "404", "file": "", "url": "", "string": ""}}
            stream = _xray_stream(panel, "naive", {"naiveSettings": {"network": "tcp"}})
        inb = panel.add_inbound(f"test-{proto}-2", ports["udp"], proto, settings,
                                stream=stream)
        return Inbound(
            protocol=proto, inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1,
            tls_sha256=stream_cert_sha256(stream))
    raise ValueError(proto)


def build_ikev2_extra(panel: Panel, server_ip: str, mode: str) -> Inbound:
    """Create an EXTRA ikev2 inbound for a NON-DEFAULT auth mode (psk | eap-tls).
    Both are SINGLE-account inbounds served by the same shared charon; the backend
    draws each device a tunnel IP from a whole-block charon pool and a reconcile
    sweep attributes usage + enforces the User Limit (web/service/ikev2.go). Returns
    the Inbound carrying whatever client-side credential the mode needs. Raises on
    panel error (or eap-tls cert-mint failure), which the caller records as a subtest
    ERROR without sinking the rest of setup.

    Nominal port only (charon owns 500/4500 for all ikev2 inbounds). K=2 so each mode
    runs the full single-account suite (User-Limit + strategy + multi-user-total +
    account-usage/termination) against the rbridge sweep, not just a connect smoke."""
    port = IKEV2_EXTRA_PORTS[mode]
    if mode == "psk":
        acct = _acct("ik2psk", 0)   # distinct email -> its own routing block
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "authMode": "psk", "psk": IKEV2_PSK, "serverAddr": "",
            "clientToClient": True, "crossInbound": True,
            "userLimit": IKEV2_EXTRA_USER_LIMIT,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-ikev2-psk", port, "ikev2", settings)
        return Inbound(
            protocol="ikev2", inbound_id=inb["id"], udp_port=port, tcp_port=0,
            accounts={"A": acct}, user_limit=IKEV2_EXTRA_USER_LIMIT,
            auth_mode="psk", psk=IKEV2_PSK, server_addr="")
    if mode == "eap-tls":
        acct = _acct("ik2tls", 0)
        # Distinct IKE server identity so the shared charon routes this conn by IDr (not
        # by auth method) — it co-resides with the primary eap-mschapv2 inbound, another
        # EAP conn, and both would otherwise present id=server_ip and collide.
        # One harness CA signs the server leaf (dNSName SAN = that identity, IP SAN =
        # server_ip) AND the client leaf. inbound.caCert = that CA: charon validates the
        # client cert against it, and the client trusts the server leaf via the same CA.
        certs = ikev2_certs.mint(server_ip, acct.email, server_id=IKEV2_EAPTLS_ID)
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "authMode": "eap-tls", "serverAddr": IKEV2_EAPTLS_ID, "tlsUseFile": False,
            "certificate": certs.server_cert, "key": certs.server_key,
            "caCert": certs.ca_cert,
            "clientToClient": True, "crossInbound": True,
            "userLimit": IKEV2_EXTRA_USER_LIMIT,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-ikev2-eap-tls", port, "ikev2", settings)
        return Inbound(
            protocol="ikev2", inbound_id=inb["id"], udp_port=port, tcp_port=0,
            accounts={"A": acct}, user_limit=IKEV2_EXTRA_USER_LIMIT,
            auth_mode="eap-tls",
            server_addr=IKEV2_EAPTLS_ID,    # -> client remote id = IDr (clients/ikev2.py)
            ca_cert=certs.ca_cert,          # client's server-trust anchor (== inbound caCert)
            client_cert=certs.client_cert,  # client leaf pushed to the client VM
            client_key=certs.client_key,
            client_id=certs.client_id)      # rfc822 SAN the client sets as `local id`
    raise ValueError(mode)


@dataclass
class Account:
    user: str
    password: str
    email: str
    index: int      # zero-based position in clients[]
    # Credentials the harness READS BACK off the panel rather than choosing, which is
    # only how the multi-inbound phase builds its accounts: there the panel mints each
    # field itself when the account joins an inbound whose protocol keys on it
    # (accountproject.go::ensureCredentialsFor), so dialling with anything else would
    # test the harness's guess instead of the projection. Empty everywhere else, and
    # every reader falls back to the historical value, so no existing phase changes.
    uuid: str = ""       # vmess / vless / tuic
    security: str = ""   # vmess cipher ("auto")
    secret: str = ""     # mtproto


@dataclass
class Inbound:
    protocol: str          # openvpn | l2tp | pptp
    inbound_id: int
    udp_port: int
    tcp_port: int          # openvpn only; 0 otherwise
    accounts: dict         # {"A": Account, "B": Account}
    psk: str = ""          # l2tp ipsec
    ovpn_udp: str = ""     # exported .ovpn profile text (openvpn)
    ovpn_tcp: str = ""
    user_limit: int = 1    # devices-per-account (User Limit feature); >1 = block mode
    # Hex SHA-256 of the DER certificate this inbound presents, for the client to pin
    # (see stream_cert_sha256). Empty for every inbound that serves no TLS.
    tls_sha256: str = ""
    ca_cert: str = ""      # ikev2: PEM CA the CLIENT must trust (server presents a leaf signed by it)
    server_addr: str = ""  # ikev2: the cert SAN the client sets as `remote id` ("" -> use server IP)
    auth_mode: str = "eap-mschapv2"  # ikev2: eap-mschapv2 (default) | psk | eap-tls
    client_cert: str = ""  # ikev2 eap-tls: client leaf PEM to push to the client VM
    client_key: str = ""   # ikev2 eap-tls: client leaf key PEM to push to the client VM
    client_id: str = ""    # ikev2 eap-tls: the client's EAP identity (rfc822 SAN) -> `local id`
    # wgc: {which: [ {deviceIndex, ip, publicKey, config}, ... ]} — the panel-minted
    # per-device client configs, fetched from the wgc-configs endpoint after build.
    wg_configs: dict = field(default_factory=dict)

    # gre: {which: [ {peerIndex, innerIp, gatewayIp, serverIp, mode, ipsecPsk, ...} ]} —
    # the router-side values rendered by the gre-configs endpoint. Its own field rather
    # than wg_configs because the shape is different (no key material, no config file:
    # a GRE peer is described by addresses and a mode).
    gre_configs: dict = field(default_factory=dict)

    # mtproto: {which: {mode: secret_hex}}, the per-account secret in each of the
    # three client-facing shapes (bare / dd… / ee…+domain), built at inbound
    # creation. MTProto has no config file to fetch: the secret IS the credential.
    mt_secrets: dict = field(default_factory=dict)

    # mtproto: {which: [mode, ...]}, the modes each account is ALLOWED, which the
    # proxy enforces per account via [access.user_modes]. Accounts deliberately
    # differ so the suite can tell per-account enforcement from per-inbound.
    mt_modes: dict = field(default_factory=dict)

    def client_ip(self, which: str, transport: str = "udp", device: int = 0) -> str:
        """Tunnel IP for account A/B on this inbound. With user_limit K>1 each
        account owns an aligned K-block: host base = (index+1)*K, device d = base+d
        (mirrors Go vpnAccountDeviceIP). K==1 keeps the legacy 2+index host."""
        if self.protocol in ("mtproto", "ssh", "anytls", "tuic", "naive"):
            # Relays and proxies: the panel assigns no tunnel address (mtproto keeps the
            # client's own IP; ssh routes per-client by the socks username=email; the
            # Xray-native three are matched by the account email carried on the session,
            # again not a source IP). Returning a plausible-looking 10.x here would be a
            # lie the routing/dns-leak checks would then act on, so fail loudly instead.
            raise AssertionError(
                f"{self.protocol} has no tunnel IP: client_ip() must not be called for it")
        acct = self.accounts[which]
        if self.protocol == "openvpn":
            base = BASE["ovpn-tcp"] if transport == "tcp" else BASE["ovpn-udp"]
        else:
            base = BASE[self.protocol]
        if self.protocol in ("wg-c", "awg", "gre") and self.user_limit > 1:
            # gateway model: one aligned power-of-two block per account; its IP is the
            # block's first address (nextPow2 rounding, mirrors Go wgcAccountBlock).
            bs = 1
            while bs < self.user_limit:
                bs <<= 1
            return f"10.{base}.{self.inbound_id}.{(acct.index + 1) * bs}"
        if self.user_limit > 1:
            host = (acct.index + 1) * self.user_limit + device
        else:
            host = 2 + acct.index
        return f"10.{base}.{self.inbound_id}.{host}"


@dataclass
class ServerConfig:
    server_ip: str
    inbounds: dict = field(default_factory=dict)   # protocol -> Inbound
    # NON-DEFAULT ikev2 auth mode -> its dedicated single-account Inbound (psk / eap-tls).
    # Kept OUT of `inbounds` on purpose: the primary suite, routing rules + translation
    # assert, bulk-ops and backup all iterate `inbounds`, so extras stay invisible to
    # them and only the ikev2 phase's per-mode block (protocols.py) consumes these.
    ikev2_extra: dict = field(default_factory=dict)
    # The classic Xray inbounds (vmess/vless/trojan/shadowsocks) the multi-inbound
    # phase builds for itself. Kept OUT of `inbounds` for the same reason as
    # ikev2_extra: bulk-ops, backup, subscription and the routing-translation assert
    # all iterate that dict, and widening it would change phases that have nothing to
    # do with this one.
    multi_inbounds: dict = field(default_factory=dict)


def _acct(prefix: str, idx: int) -> Account:
    letter = "A" if idx == 0 else "B"
    return Account(user=f"{prefix}{letter.lower()}",
                   password=f"Pw-{prefix}{letter}-9k",
                   email=f"{prefix}{letter.lower()}@t",
                   index=idx)


def run(panel: Panel, server_ip: str, cfg: dict, result: JobResult,
        log=None) -> ServerConfig | None:
    """Build inbounds/accounts/outbound/routing. Returns ServerConfig, or None
    if a fatal setup error occurred (subtests record the detail)."""
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_SETUP)
    sc = ServerConfig(server_ip=server_ip)

    # IKEv2 (strongSwan charon) and L2TP/IPsec (libreswan pluto) both bind UDP 500/4500 —
    # only ONE IKE daemon can own those ports on a host. They are mutually exclusive on a
    # single IP by design. So when the ikev2 phase is explicitly selected, run L2TP raw-only
    # (no IPsec) so charon can bind 500/4500; otherwise L2TP keeps its raw+IPsec config.
    _sel = cfg.get("_selected")
    _ikev2_sel = _sel is not None and "ikev2" in _sel

    # IKEv2 auth modes to exercise (config [ikev2] modes). Absent key -> the historical
    # single mode, so existing runs are unchanged. eap-mschapv2 is the primary inbound
    # built below; every OTHER listed mode gets its own extra single-account inbound.
    _ikev2_modes = (cfg.get("ikev2") or {}).get("modes") or ["eap-mschapv2"]
    _ikev2_extra_modes = [m for m in _ikev2_modes if m != "eap-mschapv2"]

    # ---- OpenVPN inbound ------------------------------------------------
    log("-> creating openvpn inbound (certs + 2 accounts, ciphers=all)...")
    ov = phase.add(SubTest("openvpn-inbound"))
    try:
        certs = panel.generate_openvpn_certs()
        settings = {
            "udpEnable": True, "tcpEnable": True,
            "tcpPort": 1443,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "caCert": certs["caCert"], "caKey": certs["caKey"],
            "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
            "tlsCrypt": certs["tlsCrypt"],
            "cipherMode": "all",
            # AEAD (new) + a default-provider CBC (old); both testable without
            # the OpenSSL legacy provider.
            "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            "clientToClient": True,
            "crossInbound": True,
            "userLimit": OVPN_USER_LIMIT,  # exercise the connect-hook block allocator
            "clients": [
                _dict_client(_acct("ovpn", 0)),
                _dict_client(_acct("ovpn", 1)),
            ],
        }
        inb = panel.add_inbound("test-openvpn", 1194, "openvpn", settings)
        iid = inb["id"]
        sc.inbounds["openvpn"] = Inbound(
            protocol="openvpn", inbound_id=iid, udp_port=1194, tcp_port=1443,
            accounts={"A": _acct("ovpn", 0), "B": _acct("ovpn", 1)},
            ovpn_udp=panel.download_ovpn(iid, "udp"),
            ovpn_tcp=panel.download_ovpn(iid, "tcp"),
            user_limit=OVPN_USER_LIMIT,
        )
        ov.status = Status.PASS
        ov.detail = f"inbound {iid}, udp 1194 / tcp 1443, 2 accounts, ciphers all"
    except Exception as e:  # noqa: BLE001
        ov.status = Status.ERROR
        ov.detail = str(e)[:300]

    log(f"-> openvpn-inbound [{ov.status.value}] {ov.detail}")

    # ---- L2TP inbound ---------------------------------------------------
    log("-> creating l2tp inbound (%s, 2 accounts)..." % ("raw-only, ikev2 owns 500/4500" if _ikev2_sel else "raw+ipsec"))
    l2 = phase.add(SubTest("l2tp-inbound"))
    try:
        settings = {
            "ipsecEnable": not _ikev2_sel, "ipsecPsk": PSK, "allowRaw": True,
            "clientToClient": True, "crossInbound": True,
            "userLimit": L2TP_USER_LIMIT,  # exercise the per-account block allocator
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(_acct("l2tp", 0)),
                        _dict_client(_acct("l2tp", 1))],
        }
        inb = panel.add_inbound("test-l2tp", 1701, "l2tp", settings)
        iid = inb["id"]
        sc.inbounds["l2tp"] = Inbound(
            protocol="l2tp", inbound_id=iid, udp_port=1701, tcp_port=0,
            accounts={"A": _acct("l2tp", 0), "B": _acct("l2tp", 1)}, psk=PSK,
            user_limit=L2TP_USER_LIMIT,
        )
        l2.status = Status.PASS
        l2.detail = f"inbound {iid}, {'raw-only (ikev2 owns 500/4500)' if _ikev2_sel else 'raw+ipsec, psk set'}, 2 accounts"
    except Exception as e:  # noqa: BLE001
        l2.status = Status.ERROR
        l2.detail = str(e)[:300]

    log(f"-> l2tp-inbound [{l2.status.value}] {l2.detail}")

    # ---- PPTP inbound ---------------------------------------------------
    log("-> creating pptp inbound (2 accounts)...")
    pp = phase.add(SubTest("pptp-inbound"))
    try:
        settings = {
            "clientToClient": True, "crossInbound": True,
            "userLimit": PPTP_USER_LIMIT,  # exercise the per-account block allocator
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(_acct("pptp", 0)),
                        _dict_client(_acct("pptp", 1))],
        }
        inb = panel.add_inbound("test-pptp", 1723, "pptp", settings)
        iid = inb["id"]
        sc.inbounds["pptp"] = Inbound(
            protocol="pptp", inbound_id=iid, udp_port=1723, tcp_port=0,
            accounts={"A": _acct("pptp", 0), "B": _acct("pptp", 1)},
            user_limit=PPTP_USER_LIMIT,
        )
        pp.status = Status.PASS
        pp.detail = f"inbound {iid}, 2 accounts"
    except Exception as e:  # noqa: BLE001
        pp.status = Status.ERROR
        pp.detail = str(e)[:300]

    log(f"-> pptp-inbound [{pp.status.value}] {pp.detail}")

    # ---- OpenConnect inbound --------------------------------------------
    log("-> creating openconnect inbound (self-signed cert, 2 accounts)...")
    oc = phase.add(SubTest("openconnect-inbound"))
    try:
        cert = panel.generate_ocserv_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"],
            "clientToClient": True, "crossInbound": True,
            "userLimit": OC_USER_LIMIT,  # exercise the RADIUS per-account block allocator
            "clients": [_dict_client(_acct("ocserv", 0)),
                        _dict_client(_acct("ocserv", 1))],
        }
        inb = panel.add_inbound("test-openconnect", 4443, "openconnect", settings)
        iid = inb["id"]
        sc.inbounds["openconnect"] = Inbound(
            protocol="openconnect", inbound_id=iid, udp_port=4443, tcp_port=0,
            accounts={"A": _acct("ocserv", 0), "B": _acct("ocserv", 1)},
            user_limit=OC_USER_LIMIT,
        )
        oc.status = Status.PASS
        oc.detail = f"inbound {iid}, port 4443 (TLS+DTLS), 2 accounts"
    except Exception as e:  # noqa: BLE001
        oc.status = Status.ERROR
        oc.detail = str(e)[:300]

    log(f"-> openconnect-inbound [{oc.status.value}] {oc.detail}")

    # ---- SSTP inbound ---------------------------------------------------
    # accel-ppp (PPP-over-TLS): self-signed TLS cert like openconnect, but PPP-family
    # RADIUS/accounting like pptp. Port 443 (the SSTP default the native Windows
    # client expects). The cert helper is shared with ocserv (same ECDSA self-signed).
    log("-> creating sstp inbound (accel-ppp, self-signed TLS cert, 2 accounts)...")
    ss = phase.add(SubTest("sstp-inbound"))
    try:
        cert = panel.generate_ocserv_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"],
            "clientToClient": True, "crossInbound": True,
            "userLimit": SSTP_USER_LIMIT,  # exercise the RADIUS per-account block allocator
            "clients": [_dict_client(_acct("sstp", 0)),
                        _dict_client(_acct("sstp", 1))],
        }
        inb = panel.add_inbound("test-sstp", 443, "sstp", settings)
        iid = inb["id"]
        sc.inbounds["sstp"] = Inbound(
            protocol="sstp", inbound_id=iid, udp_port=443, tcp_port=0,
            accounts={"A": _acct("sstp", 0), "B": _acct("sstp", 1)},
            user_limit=SSTP_USER_LIMIT,
        )
        ss.status = Status.PASS
        ss.detail = f"inbound {iid}, port 443 (SSTP/TLS), 2 accounts"
    except Exception as e:  # noqa: BLE001
        ss.status = Status.ERROR
        ss.detail = str(e)[:300]

    log(f"-> sstp-inbound [{ss.status.value}] {ss.detail}")

    # ---- IKEv2 inbound --------------------------------------------------
    # IKEv2/IPsec via a SINGLE shared strongSwan charon (bound to UDP 500/4500) that
    # serves every ikev2 inbound. Auth = EAP-MSCHAPv2 (server-authoritative RADIUS,
    # like ocserv). The server presents a self-signed leaf; the CLIENT must trust the
    # returned caCert — capture it on the Inbound so clients/ikev2.py can load it into
    # swanctl's x509ca dir. serverAddr left empty => leaf SAN = detected server IP, so
    # the client's `remote id = <server_ip>` matches. Port 500 is a nominal label.
    log("-> creating ikev2 inbound (shared charon, EAP-MSCHAPv2, self-signed cert+CA, 2 accounts)...")
    ik = phase.add(SubTest("ikev2-inbound"))
    try:
        cert = panel.generate_ikev2_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "authMode": "eap-mschapv2", "serverAddr": "",
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"], "caCert": cert["caCert"],
            "clientToClient": True, "crossInbound": True,
            "userLimit": IKEV2_USER_LIMIT,  # exercise the RADIUS per-account block allocator
            "clients": [_dict_client(_acct("ikev2", 0)),
                        _dict_client(_acct("ikev2", 1))],
        }
        inb = panel.add_inbound("test-ikev2", 500, "ikev2", settings)
        iid = inb["id"]
        sc.inbounds["ikev2"] = Inbound(
            protocol="ikev2", inbound_id=iid, udp_port=500, tcp_port=0,
            accounts={"A": _acct("ikev2", 0), "B": _acct("ikev2", 1)},
            user_limit=IKEV2_USER_LIMIT, ca_cert=cert.get("caCert", ""), server_addr="")
        ik.status = Status.PASS
        ik.detail = f"inbound {iid}, IKEv2/EAP (charon 500/4500), 2 accounts"
    except Exception as e:  # noqa: BLE001
        ik.status = Status.ERROR
        ik.detail = str(e)[:300]

    log(f"-> ikev2-inbound [{ik.status.value}] {ik.detail}")

    # ---- IKEv2 extra auth-mode inbounds (psk / eap-tls) -----------------
    # One dedicated single-account inbound per non-default mode, served by the SAME
    # shared charon. Built only when ikev2 is in play (_ikev2_sel: full run or
    # --tests ikev2) AND the primary inbound exists AND extra modes are configured.
    # Stored in sc.ikev2_extra so the primary suite/routing/bulk/backup are untouched;
    # protocols.py's ikev2 phase runs a per-mode connect + data-plane block on each.
    if _ikev2_sel and "ikev2" in sc.inbounds and _ikev2_extra_modes:
        for mode in _ikev2_extra_modes:
            log(f"-> creating ikev2 {mode} inbound (single account)...")
            ex = phase.add(SubTest(f"ikev2-{mode}-inbound"))
            try:
                extra = build_ikev2_extra(panel, server_ip, mode)
                sc.ikev2_extra[mode] = extra
                ex.status = Status.PASS
                ex.detail = f"inbound {extra.inbound_id}, ikev2/{mode} (port {extra.udp_port}), 1 account"
            except Exception as e:  # noqa: BLE001
                ex.status = Status.ERROR
                ex.detail = str(e)[:300]
            log(f"-> ikev2-{mode}-inbound [{ex.status.value}] {ex.detail}")

    # ---- WireGuard (C) inbound ------------------------------------------
    # In-kernel WireGuard driven by wgctrl (protocol id `wgc`, base 10.7/16). No
    # RADIUS: a peer's public key is its credential, so the rbridge sweep bills usage +
    # enforces quota/disable, and the panel mints one keypair per account. Gateway model:
    # the User Limit (6) sizes each account's aligned block (-> a /29), and its single
    # config addresses that whole block. After build we fetch each account's config.
    log("-> creating wgc inbound (kernel wireguard, gateway /29, 2 accounts, user-limit 6)...")
    wgs = phase.add(SubTest("wgc-inbound"))
    try:
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "pskEnable": False,
            "clientToClient": True, "crossInbound": True,
            "userLimit": WGC_USER_LIMIT,
            "clients": [_dict_client(_acct("wg-c", 0)),
                        _dict_client(_acct("wg-c", 1))],
        }
        inb = panel.add_inbound("test-wgc", 51820, "wg-c", settings)
        iid = inb["id"]
        wg_ib = Inbound(
            protocol="wg-c", inbound_id=iid, udp_port=51820, tcp_port=0,
            accounts={"A": _acct("wg-c", 0), "B": _acct("wg-c", 1)},
            user_limit=WGC_USER_LIMIT)
        _fetch_wg_configs(panel, wg_ib)
        sc.inbounds["wg-c"] = wg_ib
        n_cfg = sum(len(v) for v in wg_ib.wg_configs.values())
        wgs.status = Status.PASS
        wgs.detail = f"inbound {iid}, udp 51820, 2 accounts (gateway /29), {n_cfg} configs"
    except Exception as e:  # noqa: BLE001
        wgs.status = Status.ERROR
        wgs.detail = str(e)[:300]

    log(f"-> wgc-inbound [{wgs.status.value}] {wgs.detail}")

    # ---- AmneziaWG inbound ----------------------------------------------
    # Obfuscated in-kernel WireGuard (protocol id `awg`, base 10.8/16). IDENTICAL to
    # wg-c above (gateway model, no RADIUS, one keypair per account, rbridge-swept usage/
    # quota) plus the AmneziaWG obfuscation params (jc/jmin/jmax/s1/s2/h1..h4), which the
    # panel backend defaults + mints itself — so the settings here match wg-c's exactly.
    # The User Limit (6) sizes each account's aligned block (-> a /29); after build we
    # fetch each account's config (rendered by the awg-configs endpoint).
    log("-> creating awg inbound (kernel amneziawg, gateway /29, 2 accounts, user-limit 6)...")
    aws = phase.add(SubTest("awg-inbound"))
    try:
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "pskEnable": False,
            "clientToClient": True, "crossInbound": True,
            "userLimit": AWG_USER_LIMIT,
            "clients": [_dict_client(_acct("awg", 0)),
                        _dict_client(_acct("awg", 1))],
        }
        inb = panel.add_inbound("test-awg", 51825, "awg", settings)
        iid = inb["id"]
        awg_ib = Inbound(
            protocol="awg", inbound_id=iid, udp_port=51825, tcp_port=0,
            accounts={"A": _acct("awg", 0), "B": _acct("awg", 1)},
            user_limit=AWG_USER_LIMIT)
        _fetch_awg_configs(panel, awg_ib)
        sc.inbounds["awg"] = awg_ib
        n_cfg = sum(len(v) for v in awg_ib.wg_configs.values())
        aws.status = Status.PASS
        aws.detail = f"inbound {iid}, udp 51825, 2 accounts (gateway /29), {n_cfg} configs"
    except Exception as e:  # noqa: BLE001
        aws.status = Status.ERROR
        aws.detail = str(e)[:300]

    log(f"-> awg-inbound [{aws.status.value}] {aws.detail}")

    # ---- GRE inbound ----------------------------------------------------
    # Kernel ip_gre site-to-site (protocol id `gre`, base 10.9/16). Daemon-less like the
    # wg family, and the same gateway addressing model (an account owns an aligned block,
    # one address per peer router). Two things are GRE-specific:
    #   * accounts carry `peers`, each holding a customer router's public IP. Account A's
    #     is filled in AT PHASE TIME with client A's real bridge address (the harness does
    #     not know it here) so the server builds a point-to-point netdev for it; account
    #     B's is left BLANK on purpose so it is served by the shared catch-all netdev and
    #     its reverse path is learned. That covers both demux paths in one phase.
    #   * raw mode is the default (ipsecEnable=false, allowRaw=true). The phase flips the
    #     inbound to IPsec-required and to FOU for its own sub-tests.
    log("-> creating gre inbound (kernel ip_gre, 2 accounts, user-limit 2, raw mode)...")
    grs = phase.add(SubTest("gre-inbound"))
    try:
        settings = {
            "mtu": 0, "ttl": 64,
            "ipsecEnable": False, "ipsecPsk": GRE_PSK, "allowRaw": True,
            "fouEnable": False, "fouPort": 15547,
            "clientToClient": True, "crossInbound": True,
            "userLimit": GRE_USER_LIMIT,
            "clients": [_dict_client(_acct("gre", 0)),
                        _dict_client(_acct("gre", 1))],
        }
        inb = panel.add_inbound("test-gre", 47, "gre", settings)
        iid = inb["id"]
        gre_ib = Inbound(
            protocol="gre", inbound_id=iid, udp_port=47, tcp_port=0,
            accounts={"A": _acct("gre", 0), "B": _acct("gre", 1)},
            psk=GRE_PSK, user_limit=GRE_USER_LIMIT)
        _fetch_gre_configs(panel, gre_ib)
        sc.inbounds["gre"] = gre_ib
        n_cfg = sum(len(v) for v in gre_ib.gre_configs.values())
        grs.status = Status.PASS
        grs.detail = f"inbound {iid}, IP proto 47 (portless), 2 accounts, {n_cfg} peer slots"
    except Exception as e:  # noqa: BLE001
        grs.status = Status.ERROR
        grs.detail = str(e)[:300]

    log(f"-> gre-inbound [{grs.status.value}] {grs.detail}")

    # ---- MTProto Proxy inbound ------------------------------------------
    # telemt (protocol id `mtproto`). The ODD ONE: a userspace relay, so there is NO
    # tunnel, NO 10.x block, NO BASE entry and NO RADIUS. All three connection modes
    # are served at once by the single inbound: the client picks by its secret's
    # prefix: so one inbound covers the classic/secure/tls phases. Ad tag stays OFF
    # so this inbound egresses through Xray (the two are mutually exclusive; with the
    # tag on, middle-proxy mode pins egress to a direct path).
    log("-> creating mtproto inbound (telemt, all 3 modes, 2 accounts, user-limit 3)...")
    mts = phase.add(SubTest("mtproto-inbound"))
    try:
        # Both accounts hold the inbound's three modes, because the modes ARE the
        # inbound's: telemt's listener set is process-wide and its per-user map is
        # written from that same set, so a per-account subset was never a thing it
        # could enforce. The second account is still here to prove two accounts relay
        # independently on one inbound and are billed separately.
        settings = _mt_inbound_settings([_mt_client(_acct("mtproto", 0), 0),
                                         _mt_client(_acct("mtproto", 1), 1)])
        inb = panel.add_inbound("test-mtproto", MTPROTO_PORT, "mtproto", settings)
        iid = inb["id"]
        mt_ib = Inbound(
            protocol="mtproto", inbound_id=iid, udp_port=0, tcp_port=MTPROTO_PORT,
            accounts={"A": _acct("mtproto", 0), "B": _acct("mtproto", 1)},
            user_limit=MTPROTO_USER_LIMIT)
        # The panel does not mint these: we supplied them above, so build the
        # client-facing shapes locally rather than fetching them back.
        mt_ib.mt_secrets = {
            "A": _mt_secret_shapes(_MT_SECRET[0]),
            "B": _mt_secret_shapes(_MT_SECRET[1]),
        }
        # The modes every account on this inbound holds, which is the inbound's set.
        mt_ib.mt_modes = {"A": ["classic", "secure", "tls"],
                          "B": ["classic", "secure", "tls"]}
        sc.inbounds["mtproto"] = mt_ib
        mts.status = Status.PASS
        mts.detail = (f"inbound {iid}, tcp {MTPROTO_PORT}, 2 accounts, "
                      f"modes classic+secure+tls (inbound-wide), "
                      f"tls_domain {MTPROTO_TLS_DOMAIN}")
    except Exception as e:  # noqa: BLE001
        mts.status = Status.ERROR
        mts.detail = str(e)[:300]

    log(f"-> mtproto-inbound [{mts.status.value}] {mts.detail}")

    # ---- SSH inbound ----------------------------------------------------
    # In-binary Go x/crypto/ssh RELAY (protocol id `ssh`). Like mtproto it is a relay:
    # NO tunnel, NO 10.x block, NO BASE entry and NO RADIUS. Per-client routing is by the
    # account EMAIL presented as the Xray socks username (below, ssh joins the email->
    # outbound rules), so account A egresses freedom and B is blackholed even though
    # neither owns a source IP. User Limit K + strategy are INBOUND-level (in sshSettings),
    # like wg-c/mtproto. The server auto-mints + persists the ed25519 host key.
    log("-> creating ssh inbound (in-binary SSH server, 2 accounts, user-limit 2)...")
    shs = phase.add(SubTest("ssh-inbound"))
    try:
        settings = {
            "userLimit": SSH_USER_LIMIT, "userLimitStrategy": "reject",
            "clients": [_dict_client(_acct("ssh", 0)),
                        _dict_client(_acct("ssh", 1))],
        }
        inb = panel.add_inbound("test-ssh", SSH_PORT, "ssh", settings)
        iid = inb["id"]
        sc.inbounds["ssh"] = Inbound(
            protocol="ssh", inbound_id=iid, udp_port=SSH_PORT, tcp_port=0,
            accounts={"A": _acct("ssh", 0), "B": _acct("ssh", 1)},
            user_limit=SSH_USER_LIMIT)
        shs.status = Status.PASS
        shs.detail = f"inbound {iid}, tcp {SSH_PORT} (SSH relay), 2 accounts, K={SSH_USER_LIMIT}"
    except Exception as e:  # noqa: BLE001
        shs.status = Status.ERROR
        shs.detail = str(e)[:300]

    log(f"-> ssh-inbound [{shs.status.value}] {shs.detail}")

    # ---- Xray-native inbounds: anytls / tuic / naive ---------------------
    # Nothing in this harness had ever driven a client through an Xray-NATIVE inbound
    # before these three: every protocol above is served by a bundled daemon or an
    # in-binary Go server, with xray only ever downstream of it. Here xray IS the
    # server, so the account matching, the per-user stats and the limiter all run on
    # the core's own path (the contract's "set session.Inbound.User before dispatch").
    #
    # Shape per protocol comes straight from the integration contract; the trap it
    # exists to prevent is `users` vs `clients`: with the wrong tag xray prints
    # "Configuration OK", listens, ACCEPTS the connection and then fails every account,
    # while quota/expiry/disable enforcement is silently disabled too. The panel writes
    # `clients` everywhere, so that is what these post.
    #
    # 2 accounts each (A -> freedom, B -> blackhole) and NO userLimit: a device cap for
    # an Xray-native protocol is the core's per-account IP limiter (`limitIp`), a
    # different mechanism from the VPN account-slot User Limit, so leaving it at 1 keeps
    # the phase from claiming to test a feature it is not wired to.
    #
    # Transport per protocol (the `network` of streamSettings, NOT of settings):
    #   anytls -> plain tcp; TLS is an ordinary xray transport concern for it
    #   tuic   -> its own transport (QUIC), which refuses to start without TLS
    #   naive  -> its own transport, whose naiveSettings.network MUST AGREE with the
    #             proxy settings' `network`: one owns the sockets, the other the protocol
    for proto, port, remark, mk_settings, network, stream_extra in (
        ("anytls", ANYTLS_PORT, "test-anytls",
         lambda a, b: {"clients": [_dict_client(a), _dict_client(b)],
                       "paddingScheme": ANYTLS_PADDING_SCHEME},
         "tcp", None),
        ("tuic", TUIC_PORT, "test-tuic",
         lambda a, b: {"clients": [_tuic_client(a), _tuic_client(b)],
                       "congestionControl": "cubic", "authTimeout": 3,
                       "zeroRttHandshake": False, "heartbeat": 10, "udpTimeout": 60},
         "tuic", None),
        ("naive", NAIVE_PORT, "test-naive",
         lambda a, b: {"clients": [_dict_client(a), _dict_client(b)],
                       "network": NAIVE_NETWORK,
                       "masquerade": {"type": "404", "file": "", "url": "", "string": ""}},
         "naive", {"naiveSettings": {"network": NAIVE_NETWORK}}),
    ):
        log(f"-> creating {proto} inbound (xray-native, TLS, 2 accounts)...")
        xs = phase.add(SubTest(f"{proto}-inbound"))
        try:
            acct_a, acct_b = _acct(proto, 0), _acct(proto, 1)
            stream = _xray_stream(panel, network, stream_extra)
            inb = panel.add_inbound(remark, port, proto, mk_settings(acct_a, acct_b),
                                    stream=stream)
            iid = inb["id"]
            sc.inbounds[proto] = Inbound(
                # udp_port carries the listen port for every protocol whose Inbound has
                # no transport split (the ssh convention: a port LABEL), so
                # multi-inbound's per-proto `.udp_port` reads keep working. tuic really
                # is UDP (QUIC); anytls/naive are TCP.
                protocol=proto, inbound_id=iid, udp_port=port, tcp_port=0,
                accounts={"A": acct_a, "B": acct_b}, user_limit=1,
                tls_sha256=stream_cert_sha256(stream))
            xs.status = Status.PASS
            xs.detail = (f"inbound {iid}, port {port} ({network}/tls), 2 accounts "
                         f"(A freedom / B blackhole), self-signed cert")
        except Exception as e:  # noqa: BLE001
            xs.status = Status.ERROR
            xs.detail = str(e)[:300]
        log(f"-> {proto}-inbound [{xs.status.value}] {xs.detail}")

    # ---- source-IP routing rules (built-in outbounds, no external link) ----
    # Prove Xray routes by source IP using the two outbounds every config already
    # ships: `direct` (freedom) and `blocked` (blackhole). Author by email (the
    # panel auto-translates email -> source IP): A-accounts -> freedom (reach the
    # internet), B-accounts -> blackhole (cut off). The per-protocol `routing`
    # check then proves the split deterministically from the CONTRAST — same
    # protocol, adjacent tunnel IPs, only the rule differs — with no external
    # outbound and no exit-IP compare (which false-fails whenever the outbound and
    # the test host happen to share an egress IP).
    log("-> adding source-IP routing rules (A->freedom, B->blackhole)...")
    route = phase.add(SubTest("routing-rules"))
    try:
        tmpl = panel.get_xray_template()
        routing = tmpl.setdefault("routing", {})
        rules = routing.setdefault("rules", [])
        # mtproto is excluded on purpose: these rules are email->source-IP, and the
        # panel can only translate an email whose account owns a tunnel IP. MTProto
        # assigns none (it is a relay), so its emails would stay as un-matchable
        # `user` rules: routing for it is per-INBOUND, via its socks inbound's tag.
        # SSH is a relay too but is deliberately KEPT: its per-client egress IS the socks
        # username (= email), so the untranslated `user` rule matches the SSH socks account
        # directly (A->freedom, B->blackhole), which is exactly the per-client routing the
        # ssh phase asserts. So ssh joins these rules while mtproto does not.
        # anytls/tuic/naive are kept for the same reason and match even more directly: an
        # Xray-native inbound puts the account on the session itself (session.Inbound.User),
        # which is precisely what a `user` rule is compared against, so for those three
        # the rule below needs no translation of any kind to work per client.
        _routable = [ib for p, ib in sc.inbounds.items() if p != "mtproto"]
        a_emails = [ib.accounts["A"].email for ib in _routable]
        b_emails = [ib.accounts["B"].email for ib in _routable]
        # insert at the front so these win over the default catch-all / geoip rules
        rules.insert(0, {"type": "field", "outboundTag": "direct", "user": a_emails})
        rules.insert(1, {"type": "field", "outboundTag": "blocked", "user": b_emails})
        panel.update_xray_template(tmpl)
        route.status = Status.PASS
        route.detail = f"A->freedom {a_emails}, B->blackhole {b_emails}"
        route.log = (f"freedom (direct):  {', '.join(a_emails)}\n"
                     f"blackhole (blocked): {', '.join(b_emails)}")
    except Exception as e:  # noqa: BLE001
        route.status = Status.ERROR
        route.detail = str(e)[:300]

    log(f"-> routing-rules [{route.status.value}] {route.detail}")

    # ---- assert email->source-IP translation ---------------------------
    # The blackhole rule is the meaningful one: verify the panel translated the
    # B-account emails into a source-IP rule bound to `blocked`. (B is a client on
    # every inbound; openvpn B appears at both its 10.2/10.3 transport IPs.)
    log("-> verifying panel translated B emails -> source-IP (blackhole)...")
    trans = phase.add(SubTest("routing-translation"))
    try:
        want_ips = set()
        for ib in sc.inbounds.values():
            if ib.protocol in ("mtproto", "ssh", "anytls", "tuic", "naive"):
                # Relays and Xray-native proxies own no tunnel IP: mtproto is excluded
                # from the rules entirely; ssh matches by an untranslated socks-username
                # `user` rule (not a `source` one); anytls/tuic/naive match by the
                # account email xray puts on the session, which is what a `user` rule
                # compares against natively. None of them contributes a source-IP to
                # assert here.
                continue
            if ib.protocol == "openvpn":
                want_ips.add(ib.client_ip("B", "udp"))
                want_ips.add(ib.client_ip("B", "tcp"))
            else:
                want_ips.add(ib.client_ip("B"))
        conf = panel.get_config_json()
        src_seen = set()
        for r in conf.get("routing", {}).get("rules", []):
            if r.get("outboundTag") == "blocked":
                for s in r.get("source", []) or []:
                    src_seen.add(s)
        # A source may be a bare IP (K==1) or a CIDR block (User Limit K>1) — a
        # want IP counts as a hit if it equals or is contained in a seen source.
        import ipaddress as _ip
        def _covers(src: str, ip: str) -> bool:
            try:
                return _ip.ip_address(ip) in _ip.ip_network(src, strict=False)
            except ValueError:
                return src == ip
        hit = {w for w in want_ips if any(_covers(s, w) for s in src_seen)}
        trans.log = f"expected any of {sorted(want_ips)}\nsaw blackhole source {sorted(src_seen)}"
        if hit:
            trans.status = Status.PASS
            trans.detail = f"panel translated B user->source (blackhole); matched {sorted(hit)}"
        else:
            trans.status = Status.FAIL
            trans.detail = "no blackhole source-IP rule found for B accounts"
    except Exception as e:  # noqa: BLE001
        trans.status = Status.ERROR
        trans.detail = str(e)[:300]

    # ---- xray actually running with the new config ---------------------
    # Pre-inbound xray may be idle/error; now that inbounds + routing exist it
    # must run, or all tproxy->xray->internet + routing tests will fail. Restart
    # and verify, capturing logs so a backend xray failure is visible here.
    log("-> restarting xray + verifying it runs with the new config...")
    xr = phase.add(SubTest("xray-running"))
    try:
        import time as _t
        panel.restart_core("xray")
        _t.sleep(3)
        cores = {c.get("name"): c for c in panel.core_status().get("cores", [])}
        xstate = (cores.get("xray") or {}).get("state", "?")
        xr.log = f"state={xstate}\n\n== xray logs ==\n" + _safe(panel, "xray")
        if xstate in ("running", "idle"):
            xr.status = Status.PASS
            xr.detail = f"xray {xstate}"
        else:
            xr.status = Status.FAIL
            xr.detail = f"xray not running (state={xstate}) — internet/routing will fail"
        log(f"-> xray-running [{xr.status.value}] {xr.detail}")
    except Exception as e:  # noqa: BLE001
        xr.status = Status.ERROR
        xr.detail = str(e)[:300]

    # Fatal only if we couldn't build any inbound. Every protocol must be listed:
    # a protocol missing here is invisible to this check, so a run where only IT
    # succeeded would still be declared a total failure and throw the good inbound
    # away. ("wg-c" was missing until now: mtproto would have hit the same trap.)
    if all(p not in sc.inbounds for p in ("openvpn", "l2tp", "pptp", "openconnect",
                                          "sstp", "ikev2", "wg-c", "awg", "mtproto", "ssh",
                                          "anytls", "tuic", "naive")):
        return None
    return sc


def _safe(panel: Panel, core: str) -> str:
    try:
        return panel.core_logs(core)
    except Exception:  # noqa: BLE001
        return "(no logs)"


def _dict_client(a: Account) -> dict:
    return {"id": a.user, "password": a.password, "email": a.email, "enable": True}


def _fetch_wg_configs(panel: Panel, inbound: Inbound) -> None:
    """Populate inbound.wg_configs[which] with the panel-minted per-device client
    configs for every account. Best-effort per account (an empty list surfaces later
    as a clear 'no wireguard config' connect failure rather than a setup crash)."""
    inbound.wg_configs = {}
    for which, acct in inbound.accounts.items():
        try:
            inbound.wg_configs[which] = panel.wgc_configs(inbound.inbound_id, acct.email)
        except Exception:  # noqa: BLE001
            inbound.wg_configs[which] = []


def _fetch_gre_configs(panel: Panel, inbound: Inbound) -> None:
    """Populate inbound.gre_configs[which] with the panel-rendered router-side values for
    every account. Best-effort per account, so a fetch failure surfaces later as a clear
    'no GRE peer config' connect failure rather than a setup crash."""
    inbound.gre_configs = {}
    for which, acct in inbound.accounts.items():
        try:
            inbound.gre_configs[which] = panel.gre_configs(inbound.inbound_id, acct.email)
        except Exception:  # noqa: BLE001
            inbound.gre_configs[which] = []


def _fetch_awg_configs(panel: Panel, inbound: Inbound) -> None:
    """Populate inbound.wg_configs[which] with the panel-minted per-device AmneziaWG
    client configs for every account. Same shape + field (wg_configs) as wg-c: the awg
    client driver reads inbound.wg_configs exactly like the wgc driver, differing only in
    the endpoint (awg-configs) and the obfuscation params carried in the config text.
    Best-effort per account (an empty list surfaces later as a clear 'no amneziawg config'
    connect failure rather than a setup crash)."""
    inbound.wg_configs = {}
    for which, acct in inbound.accounts.items():
        try:
            inbound.wg_configs[which] = panel.awg_configs(inbound.inbound_id, acct.email)
        except Exception:  # noqa: BLE001
            inbound.wg_configs[which] = []
