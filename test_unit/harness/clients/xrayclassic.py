"""Client drivers for the CLASSIC Xray-native protocols: vmess / vless / trojan /
shadowsocks.

These four predate every VPN protocol in this fork and are the ones a 3x-ui operator
actually sells, yet nothing in this harness had ever dialled one: the suite grew up
around the bundled daemons, and the Xray-native additions (anytls/tuic/naive) arrived
with their own drivers. The multi-inbound phase needs them because an account that
spans "every protocol on the panel" is meaningless without the four that most accounts
are on.

Structurally they are the anytls/tuic/naive case exactly: xray IS the server, so there
is no tunnel device and no server-assigned address, and the client is xray too (local
socks inbound + badvpn-tun2socks on tun0). All of that lives in clients/xraytun.py;
this file is only the four outbound shapes and their transport choices.

Transport choices, and why they are not all the same:
  * vmess / vless - plain TCP, no TLS. Their own crypto is the protocol, and adding TLS
    would test the transport rather than the account matching this phase is after.
  * trojan - TLS, because trojan without TLS is not trojan: the server distinguishes a
    valid password from a probe by falling back to a decoy on mismatch, and the whole
    exchange is defined inside the TLS stream.
  * shadowsocks - plain TCP with an AEAD (non-2022) method. Deliberate: with a 2022
    method the per-user PSK must be base64 of exactly the cipher's key length, and the
    accounts layer mints ONE shared password per account across every protocol that
    keys on a password. See multi_inbound.py::ss2022_credential_check, which tests that
    collision on purpose rather than hiding from it here.
"""
from __future__ import annotations

from . import xraytun
from .base import Client

IFACE = xraytun.IFACE

# Distinct local socks port + client-side tun subnet per protocol, continuing the
# anytls(1081/56) / tuic(1082/57) / naive(1083/58) allocation. A shared port would let
# a leftover listener from an earlier phase serve tun2socks, and the phase would pass
# while testing the WRONG proxy.
SOCKS_PORT = {"vmess": 1084, "vless": 1085, "trojan": 1086, "shadowsocks": 1087}
NET_BASE = {"vmess": 59, "vless": 60, "trojan": 61, "shadowsocks": 62}

# Must match the method the inbound is created with (multi_inbound.CLASSIC_INBOUNDS).
# An AEAD method so the inbound is single-port multi-user (Xray refuses a second user
# on a stream cipher, proxy/shadowsocks/validator.go:32), and non-2022 so an ordinary
# string password is legal.
SS_METHOD = "aes-256-gcm"


def _vmess(server_ip: str, port: int, acct, spec: "xraytun.Spec") -> dict:
    """vnext shape. `id` is the account UUID as the panel projected it (acct.uuid),
    and `security` is the entry's own cipher: the projection writes both, so reading
    them back is what proves the projection produced a usable client."""
    return {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {"vnext": [{
            "address": server_ip,
            "port": port,
            "users": [{"id": acct.uuid or acct.user,
                       "security": acct.security or "auto",
                       "alterId": 0,
                       "email": acct.email}],
        }]},
        "streamSettings": {"network": "tcp", "security": "none"},
    }


def _vless(server_ip: str, port: int, acct, spec: "xraytun.Spec") -> dict:
    """vnext shape. encryption MUST be the literal "none" (VLESS carries no crypto of
    its own); omitting it is a config error, not a default."""
    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{
            "address": server_ip,
            "port": port,
            "users": [{"id": acct.uuid or acct.user,
                       "encryption": "none",
                       "email": acct.email}],
        }]},
        "streamSettings": {"network": "tcp", "security": "none"},
    }


def _trojan(server_ip: str, port: int, acct, spec: "xraytun.Spec") -> dict:
    return {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {"servers": [{
            "address": server_ip,
            "port": port,
            "password": acct.password,
            "email": acct.email,
        }]},
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            # Self-signed inbound cert (panel.generate_ocserv_cert), so verification is
            # off; the SNI still has to be a NAME because an IP is not a legal SNI.
            "tlsSettings": {"serverName": spec.sni, "allowInsecure": True},
        },
    }


def _shadowsocks(server_ip: str, port: int, acct, spec: "xraytun.Spec") -> dict:
    return {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {"servers": [{
            "address": server_ip,
            "port": port,
            "method": spec.extra.get("method", SS_METHOD),
            "password": acct.password,
            "email": acct.email,
        }]},
        "streamSettings": {"network": "tcp", "security": "none"},
    }


_BUILDERS = {"vmess": _vmess, "vless": _vless,
             "trojan": _trojan, "shadowsocks": _shadowsocks}


def spec(proto: str, **extra) -> xraytun.Spec:
    return xraytun.Spec(
        name=proto,
        socks_port=SOCKS_PORT[proto],
        net_base=NET_BASE[proto],
        outbound=_BUILDERS[proto],
        default_port=0,          # always supplied by the Inbound (udp_port label)
        dns_over_proxy=False,    # all four proxy UDP, so let DNS prove it
        extra=extra or {},
    )


SPECS = {p: spec(p) for p in _BUILDERS}


def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Signature matches the protocols.py dispatch: the protocol is read off the
    Inbound, so one function serves all four."""
    return xraytun.connect(client, inbound, which, server_ip, SPECS[inbound.protocol])


def disconnect(client: Client, proto: str = ""):
    """Kills whichever of the four is up. Called with no protocol during teardown, in
    which case every spec is swept (cheap: each is a kill + `ip link del`)."""
    for p, sp in SPECS.items():
        if proto and p != proto:
            continue
        xraytun.disconnect(client, sp)


def core_log(client: Client, proto: str, lines: int = 40) -> str:
    return xraytun.core_log(client, SPECS[proto], lines)
