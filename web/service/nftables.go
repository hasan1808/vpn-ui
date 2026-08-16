package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"
)

const nftConfigFile = "/etc/vpn-ui/vpn.nft"

// vpnAddrSpace is the covering /13 (10.0.0.0-10.7.255.255) for the protocol /16s
// VPN clients live in (10.0 L2TP, 10.1 PPTP, 10.2/10.3 OpenVPN, 10.4 OpenConnect —
// see vpnrange.go). Trusting the whole /12 in firewalld + using it as the routing
// blackhole backstop covers every current and future auto-expanded /24. It must
// stay a superset of every protocolBase /16, so widen it when adding protocols.
// Widened /13 -> /12 for AmneziaWG (base 8 -> 10.8/16): base 7 (wg-c) was the last
// /16 inside the old /13, so 10.8.x fell outside firewalld trust + the routing
// blackhole backstop until this widening. The /12 reaches 10.15.255.255, so GRE
// (base 9 -> 10.9/16) needed no further widening; bases 10-15 are still spare.
const vpnAddrSpace = "10.0.0.0/12"

// NftService manages nftables rules for L2TP, PPTP, and OpenVPN traffic accounting, TPROXY, and NAT.
type NftService struct{}

// firewalldRunning reports whether firewalld is installed and active.
func firewalldRunning() bool {
	if !commandExists("firewall-cmd") {
		return false
	}
	out, _ := exec.Command("firewall-cmd", "--state").CombinedOutput()
	return strings.TrimSpace(string(out)) == "running"
}

// ensureVpnHostNetworking relaxes the two host-level packet-filtering defaults
// that silently break VPN routing on Fedora/RHEL but not on Debian/Ubuntu — the
// reason "the VPN connects but has no internet" there:
//
//   - rp_filter: Fedora ships net.ipv4.conf.all.rp_filter=1 (strict), which drops
//     the policy-routed (fwmark → table 100) TPROXY packets on their way to the
//     Xray socket. Ubuntu defaults to loose (2); we set loose here too.
//   - firewalld: active by default on Fedora with an INPUT policy that rejects
//     everything but the explicitly opened service ports. TPROXY delivers each
//     client packet to a LOCAL socket while it still carries the client's
//     ORIGINAL destination port (e.g. 443), so firewalld's filter_INPUT drops it
//     before Xray ever sees it — control-plane auth (over the opened L2TP/PPTP/
//     OpenVPN ports) succeeds, but no data flows. Trusting the VPN source space
//     makes firewalld accept the TPROXY'd data plane.
//
// Idempotent and cheap; a no-op on hosts without an active firewalld.
func ensureVpnHostNetworking() {
	// rp_filter → loose. `all` is the effective-max override; set `default` too so
	// PPP/tun interfaces created later inherit loose rather than strict.
	for _, key := range []string{"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter"} {
		_ = exec.Command("sysctl", "-w", key+"=2").Run()
	}

	if !firewalldRunning() {
		return
	}
	// Only add the trusted source when it isn't already there. Add it to both the
	// runtime and permanent configs so no `firewall-cmd --reload` (which would drop
	// other runtime-only state) is needed.
	out, _ := exec.Command("firewall-cmd", "--zone=trusted", "--query-source="+vpnAddrSpace).CombinedOutput()
	if strings.TrimSpace(string(out)) == "yes" {
		return
	}
	if err := exec.Command("firewall-cmd", "--zone=trusted", "--add-source="+vpnAddrSpace).Run(); err != nil {
		logger.Warningf("firewalld: failed to trust VPN space %s: %v", vpnAddrSpace, err)
		return
	}
	_ = exec.Command("firewall-cmd", "--permanent", "--zone=trusted", "--add-source="+vpnAddrSpace).Run()
	logger.Infof("firewalld: trusted VPN space %s so the TPROXY data plane reaches Xray", vpnAddrSpace)
}

// writeClientToClientRules emits the inter-client (client-to-client) rules for a
// VPN inbound's client subnet(s), placed BEFORE its TPROXY rules so they take
// effect first. Traffic where BOTH src and dst are client IPs is:
//   - accepted (kernel forwards it straight to the peer) when the toggle is ON;
//   - dropped when OFF — otherwise it would be TPROXY'd to Xray, whose direct
//     outbound would still deliver it to the other client (both live on the
//     server's tun), making the toggle a no-op.
//
// Multiple subnets (OpenVPN UDP+TCP) get every src/dst pair so cross-transport
// client-to-client is covered too.
func writeClientToClientRules(b *strings.Builder, subnets []string, enabled bool) {
	verdict := "drop"
	if enabled {
		verdict = "accept"
	}
	for _, src := range subnets {
		for _, dst := range subnets {
			// The tunnel's own gateway address lives INSIDE the client subnet, so the
			// client-to-client deny would otherwise swallow it and a client could not
			// reach the address the panel tells it to route through. That is not
			// client-to-client traffic: it terminates on this host. Verified on a live
			// peer -- with the deny in place a gateway ping got 100% loss and worked the
			// moment the toggle flipped, which reads as a dead tunnel even though
			// forwarding was fine the whole time.
			//
			// Scoped to daddr INSIDE the subnet on purpose. A bare `fib daddr type local`
			// would also match the server's public address and divert client traffic away
			// from the TPROXY rules below, changing how every protocol egresses.
			if !enabled {
				b.WriteString(fmt.Sprintf(
					"add rule ip vpn prerouting ip saddr %s ip daddr %s fib daddr type local accept\n", src, dst))
			}
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip daddr %s %s\n", src, dst, verdict))
		}
	}
}

// vpnNet is one enabled VPN inbound's client address space plus its inter-client
// reachability toggles, used to build the cross-inbound rules. OpenVPN carries
// both its UDP and TCP block CIDRs.
type vpnNet struct {
	subnets []string // CIDRs, e.g. "10.0.5.0/24"
	c2c     bool     // Client to Client
	cross   bool     // Cross Inbound (UI-gated behind Client to Client)
}

// writeCrossInboundRules emits, for every pair of DIFFERENT inbounds, the verdict
// governing whether one inbound's client may reach another's: accept when BOTH
// opted into Cross Inbound (which requires Client to Client), drop otherwise.
//
// The drop is load-bearing: it sits before the per-inbound TPROXY rules, so a
// non-opted pair is dropped in the kernel instead of falling through to the
// sender's TPROXY rule, entering Xray, and being delivered to the peer by Xray's
// freedom outbound (both clients are local to this host) — which would bridge the
// two inbounds no matter how Cross Inbound is set. Same-inbound pairs are skipped
// here; they are governed by that inbound's own writeClientToClientRules.
func writeCrossInboundRules(b *strings.Builder, nets []vpnNet) {
	for ai, a := range nets {
		for bi, bnet := range nets {
			if ai == bi {
				continue
			}
			verdict := "drop"
			if a.cross && a.c2c && bnet.cross && bnet.c2c {
				verdict = "accept"
			}
			for _, sa := range a.subnets {
				for _, dst := range bnet.subnets {
					b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s ip daddr %s %s\n", sa, dst, verdict))
				}
			}
		}
	}
}

// ApplyNftRules regenerates and atomically loads the nftables config for all VPN inbounds.
// Static chains (prerouting/postrouting/input) are flushed and rebuilt.
// Accounting chains (<proto>_acct_in / <proto>_acct_out) are NEVER flushed: their dynamic
// per-client rules survive across regenerations.
func (s *NftService) ApplyNftRules() error {
	l2tp := L2tpService{}
	pptp := PptpService{}
	ovpn := OpenVpnService{}
	ocserv := OcservService{}
	sstp := SstpService{}
	ikev2 := Ikev2Service{}
	wg := WgcService{}
	awg := AwgService{}
	gre := GreService{}

	l2tpInbounds, err := l2tp.GetL2tpInbounds()
	if err != nil {
		return err
	}
	pptpInbounds, err := pptp.GetPptpInbounds()
	if err != nil {
		return err
	}
	ovpnInbounds, err := ovpn.GetOpenVpnInbounds()
	if err != nil {
		return err
	}
	ocservInbounds, err := ocserv.GetOcservInbounds()
	if err != nil {
		return err
	}
	sstpInbounds, err := sstp.GetSstpInbounds()
	if err != nil {
		return err
	}
	ikev2Inbounds, err := ikev2.GetIkev2Inbounds()
	if err != nil {
		return err
	}
	wgcInbounds, err := wg.GetWgcInbounds()
	if err != nil {
		return err
	}
	awgInbounds, err := awg.GetAwgInbounds()
	if err != nil {
		return err
	}
	greInbounds, err := gre.GetGreInbounds()
	if err != nil {
		return err
	}

	// If no VPN inbounds, remove the tables entirely
	if len(l2tpInbounds) == 0 && len(pptpInbounds) == 0 && len(ovpnInbounds) == 0 && len(ocservInbounds) == 0 && len(sstpInbounds) == 0 && len(ikev2Inbounds) == 0 && len(wgcInbounds) == 0 && len(awgInbounds) == 0 && len(greInbounds) == 0 {
		s.runCmd("nft", "delete", "table", "ip", "vpn")
		s.runCmd("nft", "delete", "table", "ip6", "vpn")
		os.Remove(nftConfigFile)
		return nil
	}

	// IPv6 confinement is driven by the same master switch that lets the tunnel
	// links negotiate IPv6 (SettingService.enableVpnIpv6). Off (the default)
	// leaves the v6 table out of the picture entirely.
	var settingService SettingService
	enableVpnIpv6, _ := settingService.GetEnableVpnIpv6()
	if !enableVpnIpv6 {
		// Drop a leftover v6 table from an earlier ON period so a later toggle
		// back does not carry stale backstop rules.
		s.runCmd("nft", "delete", "table", "ip6", "vpn")
	}

	// VPN is active — make sure the host's rp_filter/firewalld defaults don't
	// silently drop the TPROXY'd data plane (the Fedora/RHEL "connects but no
	// internet" failure). No-op on Debian/Ubuntu.
	ensureVpnHostNetworking()

	var b strings.Builder

	// Create table and chains (idempotent — 'add' doesn't error if they already exist)
	b.WriteString("add table ip vpn\n")
	for _, p := range acctProtocols {
		b.WriteString(fmt.Sprintf("add chain ip vpn %s\n", p+"_acct_in"))
		b.WriteString(fmt.Sprintf("add chain ip vpn %s\n", p+"_acct_out"))
	}
	b.WriteString("add chain ip vpn prerouting { type filter hook prerouting priority mangle; policy accept; }\n")
	b.WriteString("add chain ip vpn postrouting { type filter hook postrouting priority mangle; policy accept; }\n")
	b.WriteString("add chain ip vpn input { type filter hook input priority filter; policy accept; }\n")

	// Flush only static chains (accounting chains are dynamic, never flushed)
	b.WriteString("flush chain ip vpn prerouting\n")
	b.WriteString("flush chain ip vpn postrouting\n")
	b.WriteString("flush chain ip vpn input\n")

	// Accounting jumps (must be before TPROXY so packets are counted before accept).
	//
	// Each direction is jumped from exactly ONE hook: uplink at prerouting, downlink at
	// postrouting. A single combined chain jumped from both hooks counts a FORWARDED
	// packet twice, because such a packet traverses prerouting AND postrouting and would
	// match its direction's rule in each. TPROXY'd TCP/UDP masked that (those packets are
	// locally delivered on the way in and locally generated on the way out, so they only
	// ever see one hook), but client-to-client, cross-inbound and every non-TCP/UDP
	// protocol are forwarded and were billed at 2x. Splitting by direction is exactly
	// once under BOTH topologies.
	for _, p := range acctProtocols {
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting jump %s\n", p+"_acct_in"))
	}
	for _, p := range acctProtocols {
		b.WriteString(fmt.Sprintf("add rule ip vpn postrouting jump %s\n", p+"_acct_out"))
	}

	// --- Cross-inbound pass (mutual opt-in) --------------------------------
	// Gather every enabled VPN inbound's client subnet(s) plus its Client-to-
	// Client / Cross-Inbound toggles; writeCrossInboundRules then accepts or drops
	// each inter-inbound pair. See that function for why the drop is load-bearing.
	var allNets []vpnNet
	for _, inbound := range l2tpInbounds {
		if !inbound.Enable {
			continue
		}
		st, err := l2tp.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: subnetCIDRs(l2tp.GetSubnetsForInbound(inbound)), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	for _, inbound := range pptpInbounds {
		if !inbound.Enable {
			continue
		}
		st, err := pptp.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: subnetCIDRs(pptp.GetSubnetsForInbound(inbound)), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	for _, inbound := range ovpnInbounds {
		if !inbound.Enable {
			continue
		}
		st, err := ovpn.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: ovpnCIDRs(inbound, st), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	for _, inbound := range ocservInbounds {
		if !inbound.Enable {
			continue
		}
		st, err := ocserv.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: ocservCIDRs(inbound, st), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	for _, inbound := range sstpInbounds {
		if !inbound.Enable {
			continue
		}
		st, err := sstp.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: subnetCIDRs(sstp.GetSubnetsForInbound(inbound)), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	for _, inbound := range ikev2Inbounds {
		if !inbound.Enable {
			continue
		}
		st, err := ikev2.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: ikev2CIDRs(inbound, st), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	for _, inbound := range wgcInbounds {
		if !inbound.Enable {
			continue
		}
		st, err := wg.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: wgcCIDRs(inbound, st), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	for _, inbound := range awgInbounds {
		if !inbound.Enable {
			continue
		}
		st, err := awg.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: awgCIDRs(inbound, st), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	for _, inbound := range greInbounds {
		if !inbound.Enable {
			continue
		}
		st, err := gre.parseSettings(inbound)
		if err != nil {
			continue
		}
		allNets = append(allNets, vpnNet{subnets: greCIDRs(inbound, st), c2c: st.ClientToClient, cross: st.CrossInbound})
	}
	writeCrossInboundRules(&b, allNets)

	// L2TP TPROXY rules
	for _, inbound := range l2tpInbounds {
		if !inbound.Enable {
			continue
		}
		port := l2tp.GetTproxyPort(inbound)
		// Client-to-client gate (accept when on, drop when off) before TPROXY.
		c2c := false
		if settings, err := l2tp.parseSettings(inbound); err == nil {
			c2c = settings.ClientToClient
		}
		srcs := subnetCIDRs(l2tp.GetSubnetsForInbound(inbound))
		writeClientToClientRules(&b, srcs, c2c)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// PPTP TPROXY rules
	for _, inbound := range pptpInbounds {
		if !inbound.Enable {
			continue
		}
		port := pptp.GetTproxyPort(inbound)
		c2c := false
		if settings, err := pptp.parseSettings(inbound); err == nil {
			c2c = settings.ClientToClient
		}
		srcs := subnetCIDRs(pptp.GetSubnetsForInbound(inbound))
		writeClientToClientRules(&b, srcs, c2c)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// SSTP TPROXY rules — PPP-family like L2TP/PPTP (client /24s in 10.5.x). accel-ppp
	// terminates SSTP+PPP in userspace and assigns each client an in-range peer IP, so
	// the same source-/24 steering redirects its traffic into Xray via the inbound's
	// dokodemo port instead of NAT'ing it straight out.
	for _, inbound := range sstpInbounds {
		if !inbound.Enable {
			continue
		}
		port := sstp.GetTproxyPort(inbound)
		c2c := false
		if settings, err := sstp.parseSettings(inbound); err == nil {
			c2c = settings.ClientToClient
		}
		srcs := subnetCIDRs(sstp.GetSubnetsForInbound(inbound))
		writeClientToClientRules(&b, srcs, c2c)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// Raw L2TP filter: block non-IPsec L2TP when ipsecEnable && !allowRaw
	needFilter := false
	for _, inbound := range l2tpInbounds {
		settings, err := l2tp.parseSettings(inbound)
		if err != nil {
			continue
		}
		if settings.IpsecEnable && !settings.AllowRaw {
			needFilter = true
			break
		}
	}
	if needFilter {
		// Accept L2TP that arrived via IPsec, drop the rest
		b.WriteString("add rule ip vpn input udp dport 1701 meta secpath exists accept\n")
		b.WriteString("add rule ip vpn input udp dport 1701 drop\n")
	}

	// OpenVPN TPROXY rules — redirect client traffic into Xray (like L2TP/PPTP)
	// instead of NAT'ing it straight to the internet, so OpenVPN users obey the
	// panel's routing/outbounds. UDP clients live in 10.2.{id}.0/24 and TCP in
	// 10.3.{id}.0/24; each enabled transport is TPROXY'd to the inbound's shared
	// dokodemo port.
	for _, inbound := range ovpnInbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := ovpn.parseSettings(inbound)
		if err != nil {
			continue
		}
		port := ovpn.GetTproxyPort(inbound)
		srcs := ovpnCIDRs(inbound, settings)
		// Client-to-client gate before TPROXY. OpenVPN's own `client-to-client`
		// directive only routes within one transport's instance, so these rules
		// also cover UDP<->TCP peers and, crucially, DROP inter-client traffic
		// when the toggle is off (the directive alone can't, since Xray would
		// still bridge the two clients).
		writeClientToClientRules(&b, srcs, settings.ClientToClient)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// OpenConnect TPROXY rules — same model as OpenVPN, single block in 10.4.{id}
	// (one listener carries both TLS/TCP and DTLS/UDP), TPROXY'd to the inbound's
	// dokodemo port so ocserv clients obey the panel's routing/outbounds.
	for _, inbound := range ocservInbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := ocserv.parseSettings(inbound)
		if err != nil {
			continue
		}
		port := ocserv.GetTproxyPort(inbound)
		srcs := ocservCIDRs(inbound, settings)
		writeClientToClientRules(&b, srcs, settings.ClientToClient)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// IKEv2 TPROXY rules — same single-block model as OpenConnect, in 10.6.{id}. The one
	// shared charon decrypts ESP and the client's virtual IP (a 10.6.x source) is
	// TPROXY'd to the inbound's dokodemo port so IKEv2 users obey the panel's routing.
	for _, inbound := range ikev2Inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := ikev2.parseSettings(inbound)
		if err != nil {
			continue
		}
		port := ikev2.GetTproxyPort(inbound)
		srcs := ikev2CIDRs(inbound, settings)
		writeClientToClientRules(&b, srcs, settings.ClientToClient)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// WireGuard (C) TPROXY rules — same single-block model as IKEv2, in 10.7.{id}. The
	// kernel wireguard interface decrypts and the peer's virtual IP (a 10.7.x source) is
	// TPROXY'd to the inbound's dokodemo port so WireGuard users obey the panel's routing.
	for _, inbound := range wgcInbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := wg.parseSettings(inbound)
		if err != nil {
			continue
		}
		port := wg.GetTproxyPort(inbound)
		srcs := wgcCIDRs(inbound, settings)
		writeClientToClientRules(&b, srcs, settings.ClientToClient)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// AmneziaWG TPROXY rules — same single-block model as WireGuard (C), in 10.8.{id}.
	for _, inbound := range awgInbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := awg.parseSettings(inbound)
		if err != nil {
			continue
		}
		port := awg.GetTproxyPort(inbound)
		srcs := awgCIDRs(inbound, settings)
		writeClientToClientRules(&b, srcs, settings.ClientToClient)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// GRE rules — in 10.9.{id}. The kernel strips the GRE header before nftables sees
	// anything, so the inner packet is ordinary TCP/UDP from a 10.9.x source and rides the
	// same TPROXY rule shape as every other tunnel protocol.
	//
	// GRE needs two rule kinds none of the others do, both because it has no cryptographic
	// handshake to lean on. See GreNftView.
	//
	// The anti-spoof allow-set is aggregated PER NETDEV ACROSS EVERY INBOUND before a single
	// rule is emitted for it. That is load-bearing rather than tidy: only one unkeyed
	// catch-all may bind a given local address, so every GRE inbound on one server address
	// SHARES that netdev. Emitting one rule per inbound therefore had each inbound's rule
	// drop every other inbound's accounts (`saddr != {its own addresses} drop`), which made
	// a second GRE inbound completely unusable.
	var greViews []GreNftView
	for _, inbound := range greInbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := gre.parseSettings(inbound)
		if err != nil {
			continue
		}
		greViews = append(greViews, gre.NftView(inbound, settings))
	}
	greIfaces, greAllowedByIface, greBlocked := mergeGreViews(greViews)
	// 1. Anti-spoofing, per netdev. Without this any GRE peer could source another
	//    account's inner address and have its traffic billed to them (or bypass its own
	//    quota), because there is no per-peer crypto identity to contradict it.
	for _, iface := range greIfaces {
		addrs := greAllowedByIface[iface]
		if len(addrs) == 0 {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting iifname \"%s\" counter drop comment \"gre-antispoof-all\"\n", iface))
			continue
		}
		b.WriteString(fmt.Sprintf(
			"add rule ip vpn prerouting iifname \"%s\" ip saddr != { %s } counter drop comment \"gre-antispoof\"\n",
			iface, strings.Join(addrs, ", ")))
	}
	// 2. Hard block for accounts that are disabled, expired or over quota. Every other
	//    protocol enforces this by refusing the handshake; here the account's route and
	//    neighbour entry are withdrawn, but the promiscuous catch-all would still
	//    decapsulate its packets, so the drop has to be explicit.
	for _, cidr := range greBlocked {
		b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s counter drop comment \"gre-blocked\"\n", cidr))
	}

	for _, inbound := range greInbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := gre.parseSettings(inbound)
		if err != nil {
			continue
		}
		port := gre.GetTproxyPort(inbound)
		srcs := greCIDRs(inbound, settings)
		// Clamp TCP MSS in BOTH directions, so a customer whose path is smaller than the
		// tunnel device cannot negotiate segments the path will silently drop. GRE does not
		// negotiate MTU and PMTU discovery through it is unreliable, so without this a
		// constrained peer sees the classic black hole: small requests work, anything with
		// full-size segments hangs.
		//
		// Both rules are needed, and clamping only one is worse than it looks. A SYN's MSS
		// option constrains what the PEER sends, so the reply direction (daddr, the SYN-ACK)
		// limits the client's uploads, while the request direction (saddr, the client's own
		// SYN) is what limits every server's DOWNLOAD to it. Verified on a live customer
		// router: with only the first rule the client still advertised mss=1436 into a 1388
		// tunnel, and TLS handshakes hung on the certificate flight while small replies
		// arrived fine.
		//
		// Only the reply direction can use `rt mtu` -- see greSettings.clampMss.
		mss := settings.clampMss()
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf(
				"add rule ip vpn postrouting ip daddr %s tcp flags syn tcp option maxseg size set rt mtu counter comment \"gre-mss-clamp\"\n",
				src))
			b.WriteString(fmt.Sprintf(
				"add rule ip vpn postrouting ip saddr %s tcp flags syn tcp option maxseg size gt %d tcp option maxseg size set %d counter comment \"gre-mss-clamp-out\"\n",
				src, mss, mss))
		}
		writeClientToClientRules(&b, srcs, settings.ClientToClient)
		for _, src := range srcs {
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol tcp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
			b.WriteString(fmt.Sprintf("add rule ip vpn prerouting ip saddr %s meta mark != 0xff ip protocol udp tproxy to :%d meta mark set mark or 0x1 accept\n", src, port))
		}
	}

	// GRE raw-vs-IPsec filter. Mirrors the L2TP gate above, on protocol 47 instead of
	// UDP/1701: when IPsec is required and raw is not allowed, accept only protocol-47
	// packets that arrived inside an ESP SA (`meta secpath exists`) and drop the rest.
	// Verified against the kernel: an ESP-wrapped peer keeps working while a bare-GRE peer
	// is dropped.
	// The gate has to be scoped, because protocol 47 is demultiplexed by ADDRESS PAIR and
	// nothing else. A blanket `ip protocol 47 drop` refuses bare GRE for EVERY inbound, so
	// one inbound switched to IPsec-only used to take every other inbound's raw peers down
	// with it -- verified live: a healthy peer on another inbound went from 0% to 100% loss
	// the moment this was set, and recovered when it was cleared.
	//
	// Enforcing it after decapsulation, where the inner source identifies the account, is not
	// possible: `meta secpath exists` does NOT survive GRE decapsulation. Measured on the same
	// box, 11 inner packets from an ESP-protected peer, 0 of them matching secpath.
	//
	// So: a pinned peer is gated on its own outer address, and the blanket rule is used only
	// when NO enabled inbound allows raw, where it cannot be collateral damage.
	greIpsecOnly := false      // at least one inbound requires IPsec
	greAnyRawAllowed := false  // at least one inbound still accepts bare GRE
	var greIpsecPeers []string // pinned peers of IPsec-only inbounds
	greIpsecDynamic := []int{} // IPsec-only inbounds that also have dynamic peers
	for _, inbound := range greInbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := gre.parseSettings(inbound)
		if err != nil {
			continue
		}
		if !settings.IpsecEnable || settings.AllowRaw {
			greAnyRawAllowed = true
			continue
		}
		greIpsecOnly = true
		hasDynamic := false
		for _, client := range settings.Clients {
			for _, p := range client.peerList() {
				if ip := strings.TrimSpace(p.PeerIp); ip != "" {
					greIpsecPeers = append(greIpsecPeers, ip)
				} else {
					hasDynamic = true
				}
			}
		}
		if hasDynamic {
			greIpsecDynamic = append(greIpsecDynamic, inbound.Id)
		}
	}
	if greIpsecOnly && !greAnyRawAllowed {
		b.WriteString("add rule ip vpn input ip protocol 47 meta secpath exists accept\n")
		b.WriteString("add rule ip vpn input ip protocol 47 drop\n")
	} else if greIpsecOnly {
		sort.Strings(greIpsecPeers)
		for _, peer := range greIpsecPeers {
			b.WriteString(fmt.Sprintf(
				"add rule ip vpn input ip saddr %s ip protocol 47 meta secpath exists accept\n", peer))
			b.WriteString(fmt.Sprintf(
				"add rule ip vpn input ip saddr %s ip protocol 47 counter drop comment \"gre-ipsec-only\"\n", peer))
		}
		// Say this out loud rather than pretending the setting took effect: a dynamic peer
		// arrives on the shared catch-all and cannot be told apart from another inbound's
		// raw peer before decapsulation.
		for _, id := range greIpsecDynamic {
			logger.Warning("GRE: inbound", id,
				"requires IPsec but has dynamic peer slots while another inbound allows raw GRE;",
				"bare GRE cannot be refused for those peers - pin their peer IPs to enforce it")
		}
	}

	// IPv6 backstop: confine every tunnel's v6 to this host. Accept only what
	// terminates on the server itself (the ULA gateway, DNS, …), drop everything
	// else, so no client v6 can be forwarded out the host's real uplink — before
	// TPROXY for v6 lands (phase 4) the kernel would otherwise drop it anyway
	// (net.ipv6.conf.all.forwarding stays off), and this is the belt-and-suspenders
	// guard that keeps it that way even if something else enables forwarding.
	if enableVpnIpv6 {
		b.WriteString("add table ip6 vpn\n")
		b.WriteString("add chain ip6 vpn prerouting { type filter hook prerouting priority mangle; policy accept; }\n")
		b.WriteString("flush chain ip6 vpn prerouting\n")
		seenV6 := map[string]bool{}
		for _, n := range allNets {
			for _, s := range n.subnets {
				p := v6UlaPrefix(s)
				if p == "" || seenV6[p] {
					continue
				}
				seenV6[p] = true
				b.WriteString(fmt.Sprintf("add rule ip6 vpn prerouting ip6 saddr %s fib daddr type local accept\n", p))
				b.WriteString(fmt.Sprintf("add rule ip6 vpn prerouting ip6 saddr %s drop\n", p))
			}
		}
	}

	// Write and load atomically
	if err := os.MkdirAll("/etc/vpn-ui", 0755); err != nil {
		return err
	}
	if err := os.WriteFile(nftConfigFile, []byte(b.String()), 0644); err != nil {
		return err
	}
	if err := s.runCmd("nft", "-f", nftConfigFile); err != nil {
		return fmt.Errorf("failed to load nft rules: %w", err)
	}

	// Best-effort: drop the legacy OpenVPN NAT chain left by older versions that
	// masqueraded OpenVPN straight to the internet. OpenVPN now routes via TPROXY,
	// so the chain is obsolete. Both calls no-op once it's gone.
	s.runCmd("nft", "flush", "chain", "ip", "vpn", "nat_post")
	s.runCmd("nft", "delete", "chain", "ip", "vpn", "nat_post")

	// Best-effort: drop the pre-split combined "<proto>_acct" chains. The static chains
	// were rebuilt above without their jumps, so on an upgraded box they linger holding
	// dead rules that nothing reaches. AddClientAccounting repopulates the new direction
	// chains on the next reconcile tick. Both calls no-op once they're gone.
	for _, p := range acctProtocols {
		s.runCmd("nft", "flush", "chain", "ip", "vpn", p+"_acct")
		s.runCmd("nft", "delete", "chain", "ip", "vpn", p+"_acct")
	}

	logger.Infof("nft: loaded VPN rules (%d L2TP, %d PPTP, %d OpenVPN inbounds)", len(l2tpInbounds), len(pptpInbounds), len(ovpnInbounds))
	return nil
}

// nftCounterOutput represents the JSON output of `nft -j reset counters`.
type nftCounterOutput struct {
	Nftables []json.RawMessage `json:"nftables"`
}

type nftCounterEntry struct {
	Counter *nftCounter `json:"counter"`
}

type nftCounter struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Table   string `json:"table"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

// counterKey turns an accounting key into a valid nft counter-name fragment: a client IP
// ("10.0.2.5" -> "10_0_2_5"), or WireGuard's gateway block CIDR where the slash also maps
// to a letter ("10.7.8.8/29" -> "10_7_8_8m29"). CollectAndResetTraffic reverses it.
func counterKey(ipOrCIDR string) string {
	return strings.ReplaceAll(strings.ReplaceAll(ipOrCIDR, ".", "_"), "/", "m")
}

// nftAcctChain is the accounting chain name for one protocol and one direction, dir being
// "in" (uplink, jumped from prerouting) or "out" (downlink, jumped from postrouting).
//
// The static chains in ApplyNftRules are hyphen-free, but a protocol slug can hold a hyphen
// ("wg-c"): an nft chain name with a hyphen would not match the static "wgc_acct_in" chain,
// so the rules would target a missing chain and silently drop, counting nothing. Strip the
// hyphen so the dynamic accounting rules land in the real chain. Counter names deliberately
// keep the raw slug: they carry the protocol back to CollectAndResetTraffic via
// byProto[protocol].
func nftAcctChain(protocol, dir string) string {
	return strings.ReplaceAll(protocol, "-", "") + "_acct_" + dir
}

// acctProtocols are the protocol slugs that own a pair of accounting chains, already
// hyphen-free so they match nftAcctChain's output ("wgc", not "wg-c"). Kept in one place
// so adding a protocol means adding one entry rather than editing four rule blocks.
var acctProtocols = []string{
	"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wgc", "awg", "gre",
}

// acctRuleHandles returns the handles of every rule in `chain` that references the named
// counter, in listing order.
//
// It keys on the counter name rather than on the address text for a reason that has bitten
// twice: nft NORMALISES an address before printing it, so a host-prefix key like
// "10.7.1.2/32" (the WireGuard single-device block CIDR) is echoed back as a bare
// "10.7.1.2". Any `strings.Contains(out, "addr "+ip+" ")` test against the original key
// therefore never matches for such a client, which silently turned the add path into
// "append unconditionally" and the remove path into "delete nothing". The counter name is
// echoed verbatim and quoted, and counterKey() already makes it unique per (protocol, ip),
// so it is the one token that survives nft's formatting.
func (s *NftService) acctRuleHandles(chain, counter string) []string {
	out, err := exec.Command("nft", "-a", "list", "chain", "ip", "vpn", chain).Output()
	if err != nil {
		return nil
	}
	return acctRuleHandlesFrom(string(out), counter)
}

// acctRuleHandlesFrom is the pure half of acctRuleHandles, split out so the parse can be
// tested against real `nft -a list chain` output.
func acctRuleHandlesFrom(listing, counter string) []string {
	needle := `counter name "` + counter + `"`
	var handles []string
	for _, line := range strings.Split(listing, "\n") {
		if !strings.Contains(line, needle) {
			continue
		}
		if idx := strings.Index(line, "# handle "); idx >= 0 {
			handles = append(handles, strings.TrimSpace(line[idx+len("# handle "):]))
		}
	}
	return handles
}

// AddClientAccounting creates named nft counters and accounting rules for a VPN client.
// `ip` is a client IP, or (WireGuard gateway model) the account's block CIDR — nft matches
// either in `ip saddr`. Called by RADIUS Acct-Start / the rbridge sweep for a new session.
//
// Reconciles to EXACTLY one rule per direction. Both callers fire repeatedly for a session
// that is already live (every Acct-Start, every sweep that re-notices it), and an accounting
// chain carries no verdict, so traversal does not stop at the first match: a second copy of
// the same rule counts every packet twice and bills the account double. Extra copies are
// deleted rather than tolerated so an install that already accumulated them heals on the
// next call instead of over-billing until the session ends.
func (s *NftService) AddClientAccounting(protocol, ip string) error {
	counterIP := counterKey(ip)
	upCounter := fmt.Sprintf("%s_up_%s", protocol, counterIP)
	downCounter := fmt.Sprintf("%s_down_%s", protocol, counterIP)

	// Create counters (idempotent)
	s.runCmd("nft", "add", "counter", "ip", "vpn", upCounter)
	s.runCmd("nft", "add", "counter", "ip", "vpn", downCounter)

	s.reconcileAcctRule(nftAcctChain(protocol, "in"), upCounter, "saddr", ip)
	s.reconcileAcctRule(nftAcctChain(protocol, "out"), downCounter, "daddr", ip)

	logger.Debugf("nft: added %s accounting for %s", protocol, ip)
	return nil
}

// reconcileAcctRule leaves EXACTLY one rule in `chain` feeding `counter`, matching the
// client on `match` ("saddr" or "daddr"). Anything else present is deleted first, so an
// install that already accumulated duplicates heals here instead of over-billing until
// the session ends.
func (s *NftService) reconcileAcctRule(chain, counter, match, ip string) {
	handles := s.acctRuleHandles(chain, counter)
	if len(handles) == 1 {
		return // already exactly right
	}
	for _, h := range handles {
		s.runCmd("nft", "delete", "rule", "ip", "vpn", chain, "handle", h)
	}
	s.runCmd("nft", "add", "rule", "ip", "vpn", chain, "ip", match, ip, "counter", "name", counter)
}

// RemoveClientAccounting removes nft accounting rules and counters for a PPP client.
// Called by RADIUS Acct-Stop to stop traffic counting when a session ends.
func (s *NftService) RemoveClientAccounting(protocol, ip string) error {
	counterIP := counterKey(ip)

	// Remove every rule feeding this client's two counters, in both direction chains.
	// Matching on the counter name (not the address text) is what makes this work for a
	// /32 block CIDR. See acctRuleHandles.
	upCounter := fmt.Sprintf("%s_up_%s", protocol, counterIP)
	downCounter := fmt.Sprintf("%s_down_%s", protocol, counterIP)
	for _, dc := range []struct{ chain, counter string }{
		{nftAcctChain(protocol, "in"), upCounter},
		{nftAcctChain(protocol, "out"), downCounter},
	} {
		for _, h := range s.acctRuleHandles(dc.chain, dc.counter) {
			s.runCmd("nft", "delete", "rule", "ip", "vpn", dc.chain, "handle", h)
		}
	}

	// Delete counters
	s.runCmd("nft", "delete", "counter", "ip", "vpn", upCounter)
	s.runCmd("nft", "delete", "counter", "ip", "vpn", downCounter)

	logger.Debugf("nft: removed %s accounting for %s", protocol, ip)
	return nil
}

// ReadAndResetClientCounters atomically reads AND zeros this client's up/down
// counters, returning the byte deltas accumulated since the last collection. Call
// this right before RemoveClientAccounting on session end so those final bytes are
// persisted rather than discarded when the counters are deleted (otherwise up to a
// full 10s collection window — more under rapid reconnects — is lost from the
// client's quota). Zeroing here also stops the periodic job from double-counting
// the same bytes.
func (s *NftService) ReadAndResetClientCounters(protocol, ip string) (up, down int64) {
	counterIP := counterKey(ip)
	up = s.resetCounter(fmt.Sprintf("%s_up_%s", protocol, counterIP))
	down = s.resetCounter(fmt.Sprintf("%s_down_%s", protocol, counterIP))
	return up, down
}

// resetCounter atomically reads+zeros one named counter, returning its bytes (0 if
// missing/unparseable).
func (s *NftService) resetCounter(name string) int64 {
	out, err := exec.Command("nft", "-j", "reset", "counter", "ip", "vpn", name).Output()
	if err != nil {
		return 0
	}
	var res nftCounterOutput
	if json.Unmarshal(out, &res) != nil {
		return 0
	}
	for _, raw := range res.Nftables {
		var e nftCounterEntry
		if json.Unmarshal(raw, &e) == nil && e.Counter != nil && e.Counter.Name == name {
			return e.Counter.Bytes
		}
	}
	return 0
}

// CollectAndResetTraffic atomically reads and resets all VPN traffic counters.
// Uses `nft -j reset counters` for atomic read+reset (no race between read and zero).
// byProto maps each VPN protocol id ("l2tp", "pptp", "openvpn", "openconnect", "sstp",
// "ikev2", ...) to its IP→email session map (provided by the RADIUS service). It returns one
// combined ClientTraffic slice, one record per email with its up/down bytes summed across every
// protocol and device; AddTraffic folds these into client_traffics. Protocols absent from
// byProto are ignored, so a new protocol plugs in by adding a map entry (no signature change).
// byProtoInbound carries, per protocol, which INBOUND each tunnel address belongs
// to, so the emitted record names the source of its bytes. That is what lets the
// traffic multiplier bill at the rate of the inbound the traffic actually came
// from rather than at whichever inbound the account's single client_traffics row
// happens to name. A missing or zero entry means "unknown", which the billing
// treats as "take the max across the account's memberships".
func (s *NftService) CollectAndResetTraffic(byProto map[string]map[string]string, byProtoInbound map[string]map[string]int) []*xray.ClientTraffic {
	output, err := exec.Command("nft", "-j", "reset", "counters", "table", "ip", "vpn").Output()
	if err != nil {
		return nil
	}

	var result nftCounterOutput
	if err := json.Unmarshal(output, &result); err != nil {
		logger.Debug("nft: failed to parse counter JSON:", err)
		return nil
	}

	// Accumulate traffic per (protocol, email), matching the pre-map per-protocol record shape
	// (AddTraffic later sums by email regardless).
	type acctKey struct{ protocol, email string }
	// inboundId is the inbound the tunnel address belongs to: the SOURCE of
	// these bytes, used to pick which multiplier bills them. Zero means unknown.
	type trafficPair struct {
		up, down  int64
		inboundId int
	}
	traffic := make(map[acctKey]*trafficPair)

	for _, raw := range result.Nftables {
		var entry nftCounterEntry
		if err := json.Unmarshal(raw, &entry); err != nil || entry.Counter == nil {
			continue
		}
		c := entry.Counter
		if c.Bytes == 0 {
			continue
		}

		// Parse counter name: {protocol}_{direction}_{ip_octets_with_underscores}
		// e.g. "l2tp_up_10_0_2_10" → protocol=l2tp, dir=up, ip=10.0.2.10
		parts := strings.SplitN(c.Name, "_", 3)
		if len(parts) < 3 {
			continue
		}
		protocol := parts[0]
		direction := parts[1] // "up" or "down"
		// Reverse counterKey: "_" -> ".", and the CIDR marker "m" -> "/" (WireGuard block).
		ip := strings.ReplaceAll(strings.ReplaceAll(parts[2], "_", "."), "m", "/")

		ipMap := byProto[protocol]
		if ipMap == nil {
			continue
		}
		email, ok := ipMap[ip]
		if !ok {
			continue
		}

		pair := traffic[acctKey{protocol, email}]
		if pair == nil {
			pair = &trafficPair{}
			traffic[acctKey{protocol, email}] = pair
		}
		if pair.inboundId == 0 {
			pair.inboundId = byProtoInbound[protocol][ip]
		}
		if direction == "up" {
			pair.up += c.Bytes
		} else if direction == "down" {
			pair.down += c.Bytes
		}
	}

	var out []*xray.ClientTraffic
	for key, pair := range traffic {
		if pair.up > 0 || pair.down > 0 {
			out = append(out, &xray.ClientTraffic{Email: key.email, InboundId: pair.inboundId, Up: pair.up, Down: pair.down})
		}
	}
	if len(out) > 0 {
		logger.Debugf("nft: collected VPN traffic for %d client(s)", len(out))
	}
	return out
}

// CleanupLegacyIptables removes old iptables rules left from the pre-nftables implementation.
// All commands are idempotent (silent failure if rules don't exist).
func (s *NftService) CleanupLegacyIptables() {
	// Remove L2TP_ACCT chain
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-F", "L2TP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-X", "L2TP_ACCT")

	// Remove PPTP_ACCT chain
	s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-F", "PPTP_ACCT")
	s.runCmd("iptables", "-t", "mangle", "-X", "PPTP_ACCT")

	// Remove old raw L2TP filter
	s.runCmd("iptables", "-D", "INPUT", "-p", "udp", "--dport", "1701",
		"-m", "policy", "--dir", "in", "--pol", "none", "-j", "DROP")

	// Remove old TPROXY rules for all VPN inbounds
	l2tp := L2tpService{}
	pptp := PptpService{}

	l2tpInbounds, _ := l2tp.GetL2tpInbounds()
	for _, inbound := range l2tpInbounds {
		subnet := l2tp.GetSubnetForInbound(inbound)
		port := l2tp.GetTproxyPort(inbound)
		src := fmt.Sprintf("%s.0/24", subnet)
		s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-s", src, "-p", "tcp", "-m", "mark", "!", "--mark", "255",
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
		s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-s", src, "-p", "udp", "-m", "mark", "!", "--mark", "255",
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
	}

	pptpInbounds, _ := pptp.GetPptpInbounds()
	for _, inbound := range pptpInbounds {
		subnet := pptp.GetSubnetForInbound(inbound)
		port := pptp.GetTproxyPort(inbound)
		src := fmt.Sprintf("%s.0/24", subnet)
		s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-s", src, "-p", "tcp", "-m", "mark", "!", "--mark", "255",
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
		s.runCmd("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-s", src, "-p", "udp", "-m", "mark", "!", "--mark", "255",
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port), "--tproxy-mark", "1/1")
	}

	logger.Info("nft: cleaned up legacy iptables rules")
}

// subnetCIDRs turns "10.0.5" /24 prefixes into "10.0.5.0/24" CIDR strings.
func subnetCIDRs(subnets []string) []string {
	out := make([]string, 0, len(subnets))
	for _, p := range subnets {
		out = append(out, p+".0/24")
	}
	return out
}

// ovpnCIDRs returns the block CIDR(s) for an OpenVPN inbound's enabled
// transports (UDP => 10.2.x, TCP => 10.3.x).
func ovpnCIDRs(inbound *model.Inbound, settings *openvpnSettings) []string {
	var out []string
	if settings.udpEnabled() {
		n, p := ovpnBlockFor(inbound, settings, "udp")
		out = append(out, fmt.Sprintf("%s/%d", n.String(), p))
	}
	if settings.tcpEnabled() {
		n, p := ovpnBlockFor(inbound, settings, "tcp")
		out = append(out, fmt.Sprintf("%s/%d", n.String(), p))
	}
	return out
}

// ocservCIDRs returns the single block CIDR for an OpenConnect inbound (10.4.x).
func ocservCIDRs(inbound *model.Inbound, settings *ocservSettings) []string {
	n, p := ocservBlockFor(inbound, settings)
	return []string{fmt.Sprintf("%s/%d", n.String(), p)}
}

// ikev2CIDRs returns the single block CIDR for an IKEv2 inbound (10.6.x).
func ikev2CIDRs(inbound *model.Inbound, settings *ikev2Settings) []string {
	n, p := ikev2BlockFor(inbound, settings)
	return []string{fmt.Sprintf("%s/%d", n.String(), p)}
}

// wgcCIDRs returns the single block CIDR for a WireGuard (C) inbound (10.7.x).
func wgcCIDRs(inbound *model.Inbound, settings *wgcSettings) []string {
	n, p := wgcBlockFor(inbound, settings)
	return []string{fmt.Sprintf("%s/%d", n.String(), p)}
}

// awgCIDRs returns the single block CIDR for an AmneziaWG inbound (10.8.x).
func awgCIDRs(inbound *model.Inbound, settings *awgSettings) []string {
	n, p := awgBlockFor(inbound, settings)
	return []string{fmt.Sprintf("%s/%d", n.String(), p)}
}

func greCIDRs(inbound *model.Inbound, settings *greSettings) []string {
	n, p := greBlockFor(inbound, settings)
	return []string{fmt.Sprintf("%s/%d", n.String(), p)}
}

// mergeGreViews folds every GRE inbound's view into ONE allow-set per netdev, plus the
// combined block list. Returns the netdev names in sorted order and their sorted addresses,
// so a regenerated ruleset is byte-identical when nothing changed.
//
// Merging is REQUIRED, not cosmetic. Only one unkeyed catch-all may bind a given local
// address, so every GRE inbound on one server address shares that netdev. Emitting one
// anti-spoof rule per inbound made each inbound's rule drop every other inbound's accounts,
// which left a second GRE inbound unable to pass any traffic at all.
func mergeGreViews(views []GreNftView) (ifaces []string, allowed map[string][]string, blocked []string) {
	set := map[string]map[string]bool{}
	for _, v := range views {
		for iface, addrs := range v.Allowed {
			if set[iface] == nil {
				set[iface] = map[string]bool{}
			}
			for _, a := range addrs {
				set[iface][a] = true
			}
		}
		blocked = append(blocked, v.Blocked...)
	}
	allowed = make(map[string][]string, len(set))
	ifaces = make([]string, 0, len(set))
	for iface, addrSet := range set {
		ifaces = append(ifaces, iface)
		list := make([]string, 0, len(addrSet))
		for a := range addrSet {
			list = append(list, a)
		}
		sort.Strings(list)
		allowed[iface] = list
	}
	sort.Strings(ifaces)
	sort.Strings(blocked)
	return ifaces, allowed, blocked
}

func (s *NftService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("nft: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
