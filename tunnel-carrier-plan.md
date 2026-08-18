# Carrying a tunnel through anything

An operator names a carrier in an outbound row's **Dialer Proxy** and the tunnel's
own outer transport travels through it. Today that carrier may only be another VPN
tunnel. This makes it any Xray outbound: a `freedom` with a device pin, a vless, a
vmess, a trojan, a shadowsocks, a socks, an http, an SSH tunnel, a WARP wireguard
outbound - and it makes SSH outbounds carriable for the first time.

One control, one stored field (`Via`), one delivered meaning. What changes is only
where the carrier's **device** comes from.

## Why a device, and not a proxy

The tunnels are dialled by nine client daemons - openvpn, charon, pppd/xl2tpd, the
kernel's WireGuard, ocserv's client, sstpc, the kernel's GRE - and Xray never sees
their packets. Six of the nine cannot speak a proxy at all. What every one of them
does have is a destination address, so the panel already carries a tunnel by
POLICY ROUTING it into the carrier's netdev (`vpnoutvia.go`), which is L4-agnostic
and therefore carries GRE and ESP as well as TCP and UDP.

That mechanism stays exactly as it is. The only question this work answers is:
**given an Xray outbound tag, what device do I steer into?**

## Carrier resolution

`vpnOutCarrierFor(tag)` answers with a device, by one of four cases:

| the tag is | the device | new plumbing |
|---|---|---|
| another VPN tunnel | its `Iface` | none - this is today |
| an SSH tunnel | its carrier tun (below) | tun bridge |
| a `freedom` outbound with `sockopt.interface` | that device, directly | resolve tag -> pin |
| a `freedom` outbound with `sendThrough` | the device holding that address | resolve addr -> device |
| any other outbound (vless, vmess, trojan, ss, socks, http, wireguard, ...) | a panel-owned **carrier tun** | tun bridge |
| a `freedom` with neither, `blackhole`, `dns` | REFUSED | - |

A `freedom` outbound is a first-class carrier, and the cheapest one there is: it needs
no tun and no synthesis, because a device pin or a source address already names where
its traffic leaves, and that is exactly what a steer rule needs.

The one `freedom` that is refused is the one that names neither. That is not a limit of
this panel: `freedom` means "dial it yourself, from here", so a tunnel carried through
it would leave precisely where it already left, while every screen called it carried. It
is also the only carrier that could LOOP - every other kind dials somewhere that is not
the carried tunnel's server, so the steer rule does not catch it, whereas a bare freedom
dials that exact server and the core would hand its own packet back to itself.

## The carrier tun

Measured on 2026-08-12 against the bundled core 26.4.17, both TCP and UDP, with the
client unaware:

* The core registers `tun` as an **inbound** (`infra/conf/xray.go:36`). On Linux it
  opens `/dev/net/tun` with `IFF_TUN|IFF_NO_PI`, sets the MTU, brings the link up
  and assigns **no addresses**: `proxy/tun/README.md` says OS-level configuration of
  the interface is the operator's job. That is precisely what `vpnOutBindEgress`
  already does for every tunnel.
* **The panel owns the device.** `ip tuntap add dev <name> mode tun` first, then the
  core ATTACHES to it: measured, same ifindex before and after, and the device
  SURVIVES Xray exiting (it only goes DOWN). A stable ifindex means a stable table
  id (`vpnOutRouteTableBase + ifindex`), so the ip rules survive an Xray restart.
* A DOWN device drops its route out of the table, and the `blackhole default metric
  1000` that every tunnel table already carries then wins. **Xray down means the
  carried tunnel is blackholed, not leaked** - the existing fail-closed property,
  inherited for free.

Per carrier tag the panel therefore keeps:

    device   xcar<8 hex of the tag>        persistent, panel-created
    address  10.11.<n>.1/30               bases 10-15 are spare inside vpnAddrSpace
    table    30000 + ifindex              vpnOutBindEgress, unchanged
    inbound  {"protocol":"tun","tag":"carrier-<tag>","settings":{"name":"xcar...."}}
    rule     {"inboundTag":["carrier-<tag>"],"outboundTag":"<tag>"}   PREPENDED

The address sits inside `vpnAddrSpace` (10.0.0.0/12) so it inherits the firewalld
trust and the routing backstop; bases 10-15 are documented spare in `nftables.go`,
and 10.10 is taken by wgxray, so carriers take 10.11.

## What a carrier tun cannot carry

Measured: the tun inbound dispatches **TCP and UDP only**. ICMP is dropped (ping
through it: 100% loss, and `proxy/tun/README.md` says so). Raw IP protocols - GRE
(47) and ESP (50) - are not dispatched either.

So a tunnel rides an Xray outbound if and only if its outer transport is TCP or UDP:

| kind | outer transport | through a device carrier | through an Xray outbound |
|---|---|---|---|
| wireguard | UDP | yes | yes, no driver change |
| awg | UDP | yes | yes, no driver change |
| openvpn | TCP or UDP | yes | yes, no driver change |
| openconnect | TCP 443 (+ DTLS UDP) | yes | yes, no driver change |
| sstp | TCP 443 | yes | yes, no driver change |
| ssh | TCP | yes | yes, SSH gained `Via` |
| l2tp, no PSK | UDP 1701 | yes | yes, already pure UDP |
| ikev2 | UDP 500/4500 + **ESP** | yes | yes, `encap = yes` forced when carried |
| l2tp/ipsec | UDP 1701/500/4500 + **ESP** | yes | yes, `encap = yes` forced when carried |
| gre, FOU | UDP | yes | yes |
| gre, IPsec | **ESP** | yes | yes, `encap = yes` forced when carried |
| gre, raw | **IP proto 47** | yes | refused: turn on FOU or IPsec |
| pptp | TCP 1723 + **GRE proto 47** | yes | **impossible** |

Forcing encapsulation is conditional on being carried, never unconditional, and it is
VERIFIED rather than assumed. strongSwan's IKEv1 NAT-D path gives up when the peer sends
no NAT-T vendor ID, so the SA installs as raw ESP with the config still saying
`encap = yes` - and it fails in the worst possible shape: the SA reports ESTABLISHED, the
tunnel reports up, and nothing crosses because the carrier drops proto 50. So the drivers
read the negotiated state back out of `swanctl --list-sas` (the human listing spells it
`TRANSPORT-in-UDP` / `TUNNEL-in-UDP`, not `encap: yes`, which appears only under `--raw`)
and fail the bring-up naming the cause.

PPTP is the one honest refusal, and raw GRE the one that names a setting instead. PPTP's
control channel would ride and its data channel would not, which is worse than refusing:
the link would authenticate, report itself up, and move nothing. Both refusals name the
alternative that does work - a VPN tunnel, or a `freedom` outbound with a device pin,
either of which carries them today and always did.

## Loops

Xray must never dial its own uplink through its own tun. The panel steers only the
carried tunnel's server addresses, never a default route, so a loop needs the
carrier's uplink and the carried tunnel's server to be the same address. The
exclusion band in `vpnoutvia.go` already exists for exactly this and is extended to
cover a carrier outbound's own server address, read out of the outbound template.

A plain `freedom` carrier is the one case where the loop is structural - it dials
the carried tunnel's server directly, and that destination is steered into the tun.
It is refused at save.

## Fail-closed, restated

1. Carrier tunnel or device gone -> blackhole in the table, traffic dropped.
2. Xray stopped -> carrier tun goes DOWN -> same blackhole, traffic dropped.
3. Carrier tag that resolves to nothing -> refused at save, before anything is raised.
4. Carried kind whose outer cannot ride the carrier -> refused at save, naming the
   kind and what to do instead.
