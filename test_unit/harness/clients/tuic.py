"""TUIC client driver: an xray tuic outbound turned into a system tunnel.

Everything structural lives in clients/xraytun.py. This file is only the TUIC-specific
parts: the outbound settings, and the UDP relay mode.

UDP is TUIC's main risk and the reason this driver is parameterised. TUIC carries UDP
two different ways and the panel's share links advertise one of them:

  * `udpRelayMode: "native"`  - one QUIC datagram per UDP packet (unreliable, MTU-bound)
  * `udpRelayMode: "quic"`    - UDP over a QUIC stream (`udpStream`, reassembled by the
                                server's defragmenter)

They are entirely separate code paths on both ends, so a green run on one says nothing
about the other. `connect_mode()` dials a chosen mode and protocols.py runs the UDP
subtest against BOTH.

Transport: `"network": "tuic"` is a real xray transport (transport/internet/tuic), and
the server side rejects a config with no TLS ("TUIC requires TLS") and pins ALPN to h3
(`WithNextProto("h3")`), so the client must offer h3 or the handshake dies with an
opaque "tls: no application protocol".
"""
from __future__ import annotations

from . import xraytun
from .base import Client

SOCKS_PORT = 1082
IFACE = xraytun.IFACE

# The two carriers, in the order protocols.py exercises them. "native" is the default
# every client (and the panel's own share link) uses.
UDP_MODES = ("native", "quic")


def _outbound(server_ip: str, port: int, acct, spec: "xraytun.Spec") -> dict:
    """The tuic client outbound, shaped after infra/conf's TuicClientConfig: a flat
    address/port/id/password (which the parser expands into its single-entry
    `servers` list), plus the congestion + UDP knobs."""
    return {
        "tag": "proxy",
        "protocol": "tuic",
        "settings": {
            "address": server_ip,
            "port": port,
            # Derived from the email for the accounts THIS harness creates (server_setup
            # builds the inbound with the same derivation, so the two cannot drift), but
            # an account minted by the panel carries its own uuid and hands it over in
            # acct.uuid — see server_setup.Account.
            "id": acct.uuid or xraytun.tuic_uuid(acct.email),
            "password": acct.password,
            "email": acct.email,
            "congestionControl": "cubic",
            "udpRelayMode": spec.extra.get("udp_mode", "native"),
            "zeroRttHandshake": False,
            "heartbeat": 10,
        },
        "streamSettings": {
            "network": "tuic",
            "security": "tls",
            # alpn h3 is MANDATORY: the server forces it, and a client that offers
            # nothing fails with an error that names nothing an operator can act on.
            "tlsSettings": {"serverName": spec.sni, "allowInsecure": True,
                            "alpn": ["h3"]},
        },
    }


def _spec(udp_mode: str = "native") -> xraytun.Spec:
    return xraytun.Spec(
        name="tuic",
        socks_port=SOCKS_PORT,
        net_base=57,
        outbound=_outbound,
        default_port=8448,
        dns_over_proxy=False,   # UDP is native to TUIC; let DNS prove it
        extra={"udp_mode": udp_mode},
    )


SPEC = _spec()


def connect(client: Client, inbound, which: str,
            server_ip: str = "") -> tuple[bool, str, str]:
    """Signature matches the protocols.py dispatch. Uses the default UDP relay mode
    ("native"), the one the panel's share link advertises."""
    return xraytun.connect(client, inbound, which, server_ip, SPEC)


def connect_mode(client: Client, inbound, which: str, server_ip: str,
                 udp_mode: str) -> tuple[bool, str, str]:
    """Dial with an explicit UDP relay mode ("native" | "quic") so the UDP subtest can
    prove BOTH carriers rather than whichever one happens to be the default."""
    return xraytun.connect(client, inbound, which, server_ip, _spec(udp_mode))


def disconnect(client: Client):
    xraytun.disconnect(client, SPEC)
