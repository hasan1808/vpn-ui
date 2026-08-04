"""AnyTLS client driver: an xray anytls outbound turned into a system tunnel.

Everything structural lives in clients/xraytun.py (local socks inbound + the outbound
below, badvpn-tun2socks on tun0, split-default routes, tunnel DNS). This file is only
the parts that are specific to AnyTLS.

UDP: AnyTLS has NO UDP transport of its own. The client wraps UDP in the same TLS
stream (UoT, addressed to `sp.v2.udp-over-tcp.arpa`) and the server unwraps it. That
interception is a named risk in the integration contract, so this driver deliberately
does NOT route DNS around it: UDP:53 goes through the outbound like any other
datagram, which makes the shared dns-resolve / dns-leak checks a real test of UoT. If
UoT is missing on either end, DNS dies and the phase fails loudly rather than passing
on a TCP fallback.
"""
from __future__ import annotations

from . import xraytun
from .base import Client

# Local socks port. Distinct per protocol on purpose: a leftover listener from an
# earlier phase (ssh uses 1080) would otherwise quietly serve tun2socks, and the whole
# phase would pass while testing the WRONG proxy.
SOCKS_PORT = 1081
IFACE = xraytun.IFACE


def _outbound(server_ip: str, port: int, acct, spec: "xraytun.Spec") -> dict:
    """The anytls client outbound.

    Settings shape follows proxy/anytls's ClientConfig (one address/port/password:
    there is no repeated `servers` field in its proto, unlike vmess/shadowsocks), so
    the JSON is flat. TLS is a normal xray transport concern: AnyTLS gets it for free
    from streamSettings, which is the whole point of the protocol's name."""
    return {
        "tag": "proxy",
        "protocol": "anytls",
        "settings": {
            "address": server_ip,
            "port": port,
            "password": acct.password,
            "email": acct.email,
        },
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            # The inbound presents a self-signed cert (panel.generate_ocserv_cert), so
            # the client must skip verification; the SNI still has to be a NAME because
            # an IP is not a legal SNI value.
            "tlsSettings": {"serverName": spec.sni, "allowInsecure": True},
        },
    }


SPEC = xraytun.Spec(
    name="anytls",
    socks_port=SOCKS_PORT,
    net_base=56,
    outbound=_outbound,
    default_port=8447,
    dns_over_proxy=False,   # UDP rides UoT; see the module docstring
)


def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Signature matches the protocols.py dispatch: connect(client, inbound, which,
    server_ip=...). The listen port is read from inbound.udp_port (a port label reused
    across protocols so multi-inbound's per-proto `.udp_port` reads work)."""
    return xraytun.connect(client, inbound, which, server_ip, SPEC)


def disconnect(client: Client):
    xraytun.disconnect(client, SPEC)
