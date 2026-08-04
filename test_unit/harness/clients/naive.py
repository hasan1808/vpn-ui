"""NaiveProxy client driver: an xray naive outbound turned into a system tunnel.

Everything structural lives in clients/xraytun.py. This file is only the naive-specific
parts.

UDP: naive is HTTP CONNECT over h2/h3 and proxies NO UDP at all. The `network` field
picks the CARRIER (tcp = HTTP/2, udp = HTTP/3), not what it can forward: an h3 naive
still cannot carry a UDP payload. So this is the one driver that
sets `dns_over_proxy`: xray answers UDP:53 locally from its own resolver, whose
upstreams are `tcp://` and therefore query THROUGH the proxy. That is what a real
naive deployment must do, and it keeps DNS inside the tunnel. The alternative (let
the resolver fall through to the physical route) would turn dns-leak green while DNS
bypassed the proxy entirely.

Everything else UDP stays unsupported on purpose: protocols.py records naive's UDP
subtest as NA with that reason rather than inventing a path for it.
"""
from __future__ import annotations

from . import xraytun
from .base import Client

SOCKS_PORT = 1083
IFACE = xraytun.IFACE


def _outbound(server_ip: str, port: int, acct, spec: "xraytun.Spec") -> dict:
    """The naive client outbound.

    Credentials: naive sends ONE `Proxy-Authorization: Basic base64(email:password)`.
    the username IS the account email, which is also how the server maps the request
    back to an account.

    Transport: `network: "tcp"` selects the h2 carrier, and on that path the outbound
    dials an ORDINARY tcp+tls stream (the `naive` transport in streamSettings is the h3
    dialer, and is only reached when the outbound's own network is "udp"). h2 has to be
    in the ALPN list explicitly: the client checks the negotiated protocol and refuses
    anything else with "set alpn: [h2] in tlsSettings"."""
    return {
        "tag": "proxy",
        "protocol": "naive",
        "settings": {
            "address": server_ip,
            "port": port,
            "email": acct.email,
            "password": acct.password,
            "network": "tcp",
        },
        "streamSettings": {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"serverName": spec.sni, "allowInsecure": True,
                            "alpn": ["h2"]},
        },
    }


SPEC = xraytun.Spec(
    name="naive",
    socks_port=SOCKS_PORT,
    net_base=58,
    outbound=_outbound,
    default_port=8449,
    dns_over_proxy=True,    # naive carries no UDP; see the module docstring
)


def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Signature matches the protocols.py dispatch."""
    return xraytun.connect(client, inbound, which, server_ip, SPEC)


def disconnect(client: Client):
    xraytun.disconnect(client, SPEC)
