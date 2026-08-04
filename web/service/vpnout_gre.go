package service

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/goccy/go-json"
)

// GRE as an OUTBOUND: the panel dials out as the CLIENT of somebody else's GRE server.
//
// GRE is perfectly symmetric, so this is the same netlink.Gretun the server side builds in
// gre.go with local and remote swapped: our public address is `local`, theirs is `remote`,
// and the inner address they assigned us goes on the device. Everything gre.go learned the
// hard way applies unchanged and is respected here:
//
//   - PMtuDisc MUST be set explicitly. The netlink library sends IFLA_GRE_PMTUDISC with no
//     nil-guard, so the zero value does not mean "default", it means PMTU discovery
//     DISABLED. ensureGretun (reused from gre.go) is the one place that gets this right,
//     which is why the device is created through it rather than through a private copy.
//   - EXACT TUPLE, never a wildcard. A client always knows its peer, so `local X remote Y`
//     is the natural shape anyway, and it is also the one that coexists with whatever
//     catch-all the GRE *server* side of this same panel may have bound to the same local
//     address: the kernel prefers the exact match, so an outbound tunnel to a third party
//     cannot steal a customer's packets and vice versa.
//   - NO NEIGHBOUR ENTRIES. NeighSet exists on the server because its shared catch-all has
//     `remote any` and has to learn where each inner address lives. With an exact remote the
//     kernel already knows where to send, so there is nothing to learn and nothing to set.
//   - FOU needs GRO OFF on the interface that RECEIVES the encapsulated packets, or nearly
//     every segment is lost while a trickle survives. See greOutEnsureFou.
//
// THE DEVICE NAME MUST NOT START WITH "gre". GreService.removeStaleLinks deletes every
// netlink.Gretun whose name starts with greP2pPrefix ("gre") and is not in the plan it just
// computed from the inbounds table, and it runs on EVERY traffic-job tick. An outbound
// tunnel is not in that plan and never will be, so a name like "gre-out0" would be silently
// deleted within seconds of coming up. Hence the "cgre" prefix (client GRE), which that
// prefix scan does not match.
//
// THE DEVICE MTU IS THE MSS CLAMP HERE, and that is why the per-encapsulation defaults are
// copied from the server side rather than left to the kernel. The inbound path needs TWO
// explicit nftables rules (gre-mss-clamp and gre-mss-clamp-out) because the panel FORWARDS a
// customer's TCP there: it is a middlebox, so it has to rewrite the MSS option on SYNs going
// both ways, and clamping only the reply direction (`rt mtu`, which resolves to the WAN on the
// request side) limits uploads while leaving every full-size download to black-hole. An
// OUTBOUND tunnel forwards nothing. Xray terminates the client's connection and ORIGINATES a
// new one out of this device, so every segment crossing it is locally generated, and for a
// locally generated connection the kernel derives the advertised MSS from the route it is
// using. That route carries no MTU or advmss metric, whether it is the framework's plain
// `default dev <tunnel>` or the kernel's own on-link fallback, so ipv4_default_advmss falls
// back to the DEVICE MTU minus 40. That limits what the far end sends us (downloads), while
// our own sends are limited by the same MTU and by the peer's advertised MSS (uploads). Both
// directions therefore follow the device MTU, one number, and no packet-path rules are needed.
// Nor could they be added here: NftService.ApplyNftRules flushes and rebuilds the whole `vpn`
// table from inbound state, so anything this driver wrote into it would disappear on the next
// inbound change.
//
// THIS DRIVER INSTALLS NO ROUTES AND NO IP RULES. Egress belongs to the framework, which
// calls vpnOutBindEgress after Up and gives every tunnel the same private routing table plus
// an `oif` rule; nothing of ours goes near the main table, so the host's own default route is
// never at risk. Worth knowing while reading this file: even with none of that, a socket
// pinned with SO_BINDTODEVICE still reaches the far side, because when an explicit oif is set
// and the FIB lookup finds nothing the kernel assumes the destination is on-link out of that
// device and builds the route anyway (net/ipv4/route.c, "Apparently, routing tables are
// wrong"). Verified on a live kernel: `ip route get 1.1.1.1 oif <dev>` resolves through a
// route-less GRE device while `ip route get 1.1.1.1` still answers via the WAN. So the driver
// owes the framework a device with an address on it, and nothing more.
const (
	// greOutPrefix names the client netdevs. Deliberately NOT "gre" (see above).
	greOutPrefix = "cgre"
	// greOutIfMax is IFNAMSIZ-1: 16 bytes including the NUL terminator.
	greOutIfMax = 15
)

// greOutSettings is the GRE slice of one outbound tunnel's opaque Settings blob.
//
// The three modes mirror the server's matrix (raw, FOU, IPsec) because the operator is
// dialling a server that offers exactly those, quite possibly one of these panels: the
// values here are the ones gre.go's RenderPeerConfigs hands a customer, so a tunnel between
// two vpn-ui boxes is a copy-paste away.
type greOutSettings struct {
	// Server is the remote GRE endpoint. A hostname is accepted and resolved once, at Up:
	// the kernel tunnel takes an ADDRESS, not a name, and GRE has no ports and no keepalive
	// to re-resolve on, so a moving remote has to be re-saved.
	Server string `json:"server"`
	// Local is our outer source address. Empty means "whatever address this host egresses
	// to the internet with", which is right for a single-homed box and wrong for exactly
	// the operator who knows it is wrong, so it is exposed rather than assumed.
	Local string `json:"local"`
	// Address is the inner address the far side assigned us, with an optional prefix
	// ("10.9.1.5" or "10.9.1.5/32"). REQUIRED, and not a formality: the device is what
	// source-address selection reads once the socket is pinned to it, so a GRE device with
	// no address makes the kernel fall back to another interface's address and the far side
	// receives packets it has no route back for.
	Address string `json:"address"`
	// Peer is the far side's inner address (their gateway). Purely informational: a
	// point-to-point GRE device sends everything to its `remote` outer address, so nothing is
	// routed by this and leaving it empty costs nothing. It is kept because it is the value
	// the far side's recipe hands out next to the tunnel address, it is what an operator
	// pings to prove the tunnel carries traffic, and dropping it would mean asking for half
	// of a pair of numbers.
	Peer string `json:"peer"`

	Mtu int `json:"mtu"`
	Ttl int `json:"ttl"`

	FouEnable bool `json:"fouEnable"`
	FouPort   int  `json:"fouPort"`

	IpsecEnable bool   `json:"ipsecEnable"`
	IpsecPsk    string `json:"ipsecPsk"`
	// IpsecRemoteId is the identity the far side presents. A vpn-ui GRE inbound presents
	// "gre-<inbound id>.vpn-ui" (greIkeID), and its recipe tells the customer to pin it,
	// because a shared charon with several PSKs cannot otherwise tell which key to use.
	IpsecRemoteId string `json:"ipsecRemoteId"`
	// IpsecLocalId is the identity WE present. Empty means our local address, which is what
	// charon defaults to and what most responders expect.
	IpsecLocalId string `json:"ipsecLocalId"`
	// IpsecIkeVersion is 0 (the default: accept either, initiate IKEv2), 1 or 2. Worth
	// exposing even though the default is nearly always right, because "1" is the only thing
	// that gets a tunnel up against an older router that answers nothing at all to an IKEv2
	// proposal, and there is no way to discover that from this side.
	IpsecIkeVersion int `json:"ipsecIkeVersion"`
}

// greOutDriver implements VpnOutDriver for kind "gre".
type greOutDriver struct{}

func init() { RegisterVpnOutDriver(VpnOutGre, greOutDriver{}) }

// SecretKeys names the one field here that must never reach the browser.
//
// GRE is unusually easy to answer for, because the protocol carries no credential at all:
// there is nothing to authenticate, so the only secret in the whole config is the pre-shared
// key of the OPTIONAL IPsec wrapper. Everything else (both endpoints, the inner addresses, the
// MTU, the FOU port, the IKE identities) is either public by nature or visible to anyone who
// can see the packets, and the form needs all of it.
//
// Deliberately NOT listed: ipsecRemoteId and ipsecLocalId. An IKE identity is sent in the
// clear during the exchange and the far side's recipe prints it; masking it would only stop
// the operator checking the one field that is most often mistyped.
func (greOutDriver) SecretKeys() []string { return []string{"ipsecPsk"} }

// Available reports whether this host can carry a GRE tunnel at all.
//
// Nothing is bundled for GRE (the data plane is the in-tree ip_gre module and netdevs this
// driver reconciles), so the only way it can be unusable is a kernel without that module,
// which does happen on cut-down cloud and container kernels. GreAvailable already handles the
// case that matters most for a false negative: ip_gre is frequently built INTO the kernel
// rather than as a module, where there is no /sys/module entry to find but GRE works
// perfectly, and the fallback device the module registers is the reliable tell.
// No core is named as the fix even though the catalog has a GRE one: it declares only
// the optional fou module and installs no kernel package at all, so an operator sent to
// Core Settings would find nothing there that produces ip_gre. The module ships with the
// kernel, and on the cut-down cloud images where it is missing it comes back with the
// distribution's fuller modules package, which is what pkgmgr.go installs for the cores
// that do claim featKernelMods.
func (greOutDriver) Available() (bool, string) {
	if (&GreService{}).GreAvailable() {
		return true, ""
	}
	return false, "this kernel has no GRE support (module ip_gre). It ships with the kernel rather than " +
		"with the panel, so install your distribution's full kernel modules package " +
		"(linux-modules-extra on Debian and Ubuntu, kernel-modules-extra on the RHEL family)"
}

// greOutIfName maps a tag to a bounded, deterministic netdev name.
//
// Deterministic matters more than pretty: Down and Status are handed nothing but the stored
// config, so the name has to be recomputable from the tag alone. A tag that is already a
// legal short device name is used as-is with a dash, because an operator debugging with `ip
// -s link` should be able to find their tunnel; anything else is hashed. The two forms
// cannot collide because only the readable one contains a dash.
func greOutIfName(tag string) string {
	safe := strings.TrimSpace(tag)
	if len(safe) > 0 && len(safe) <= greOutIfMax-len(greOutPrefix)-1 && greOutPlainName(safe) {
		return greOutPrefix + "-" + safe
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(tag))
	return fmt.Sprintf("%s%08x", greOutPrefix, h.Sum32())
}

func greOutPlainName(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func greOutParse(cfg VpnOutboundConfig) (*greOutSettings, error) {
	st := &greOutSettings{}
	if len(cfg.Settings) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(cfg.Settings, st); err != nil {
		return nil, fmt.Errorf("gre outbound: unreadable settings: %w", err)
	}
	return st, nil
}

// greOutMtu is the inner MTU for this tunnel: the operator's value, else the largest that
// fits the encapsulation actually in use. Same order of precedence as the server's
// effectiveMtu, and for the same reason: when both IPsec and FOU are on the packet pays both
// overheads, so the smaller has to win or full-size packets black-hole.
func (o *greOutSettings) greOutMtu() int {
	if o.Mtu > 0 {
		return o.Mtu
	}
	if o.IpsecEnable {
		return greKernelMtuIpsec
	}
	if o.FouEnable {
		return greKernelMtuFou
	}
	return greKernelMtuRaw
}

func (o *greOutSettings) greOutTtl() uint8 {
	if o.Ttl > 0 && o.Ttl < 256 {
		return uint8(o.Ttl)
	}
	return greDefaultTTL
}

func (o *greOutSettings) greOutFouPort() int {
	if o.FouPort > 0 && o.FouPort < 65536 {
		return o.FouPort
	}
	return greDefaultFouPort
}

// greOutInner splits the configured inner address into an IP and a prefix length, defaulting
// to /32. A /32 is what the server's own recipe hands out (`ip addr add <inner>/32`): the
// device is point to point, so there is no subnet on it to be a member of.
func greOutInner(addr string) (net.IP, int, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, 0, fmt.Errorf("the tunnel address the remote assigned you is required")
	}
	if strings.Contains(addr, "/") {
		ip, ipnet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, 0, fmt.Errorf("tunnel address %q is not a valid address/prefix", addr)
		}
		if ip.To4() == nil {
			return nil, 0, fmt.Errorf("tunnel address %q is not IPv4", addr)
		}
		ones, _ := ipnet.Mask.Size()
		return ip.To4(), ones, nil
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return nil, 0, fmt.Errorf("tunnel address %q is not a valid IPv4 address", addr)
	}
	return ip.To4(), 32, nil
}

// greOutResolve turns the configured remote into an IPv4 address. A name is resolved on the
// HOST's resolver, before any tunnel exists, which is the only resolver available at this
// point and the correct one: the outer packets travel over the host's own network.
func greOutResolve(host string) (net.IP, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("the remote GRE server address is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("remote %q is IPv6; this driver builds IPv4 GRE tunnels", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve remote %q: %w", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("remote %q has no IPv4 address", host)
}

// greOutLocal resolves our outer source address: the operator's value when set, else the
// address the routing table says this host egresses with.
func greOutLocal(st *greOutSettings) (net.IP, error) {
	if l := strings.TrimSpace(st.Local); l != "" {
		ip := net.ParseIP(l)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("local address %q is not a valid IPv4 address", l)
		}
		return ip.To4(), nil
	}
	if ip := primaryV4Addr(); ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("cannot work out this host's own address; set the local address explicitly")
}

// Validate refuses a config while the modal is still open, so a tunnel that could never work
// is never brought up and never written into the outbound list.
func (greOutDriver) Validate(cfg VpnOutboundConfig) error {
	st, err := greOutParse(cfg)
	if err != nil {
		return err
	}
	if _, err := greOutResolve(st.Server); err != nil {
		return err
	}
	if _, _, err := greOutInner(st.Address); err != nil {
		return err
	}
	if _, err := greOutLocal(st); err != nil {
		return err
	}
	if p := strings.TrimSpace(st.Peer); p != "" {
		if ip := net.ParseIP(p); ip == nil || ip.To4() == nil {
			return fmt.Errorf("remote tunnel address %q is not a valid IPv4 address", p)
		}
	}
	if st.Mtu != 0 && (st.Mtu < 576 || st.Mtu > 9000) {
		return fmt.Errorf("MTU %d is outside the usable range (576-9000)", st.Mtu)
	}
	if st.Ttl < 0 || st.Ttl > 255 {
		return fmt.Errorf("TTL %d is outside 0-255", st.Ttl)
	}
	if st.FouEnable {
		if st.FouPort != 0 && (st.FouPort < 1 || st.FouPort > 65535) {
			return fmt.Errorf("FOU port %d is outside 1-65535", st.FouPort)
		}
		if !(&GreService{}).FouAvailable() {
			return fmt.Errorf("this kernel has no FOU support (module 'fou'), so UDP-encapsulated GRE cannot be used here")
		}
	}
	if st.IpsecEnable {
		if strings.TrimSpace(st.IpsecPsk) == "" {
			return fmt.Errorf("IPsec is enabled but no pre-shared key was given")
		}
		switch st.IpsecIkeVersion {
		case 0, 1, 2:
		default:
			return fmt.Errorf("IKE version %d is not one of 0 (either), 1 or 2", st.IpsecIkeVersion)
		}
	}
	// Checked last, because it is a property of the host rather than of what was typed and
	// the field-level messages are the more useful ones to show first.
	if !(&GreService{}).GreAvailable() {
		return fmt.Errorf("this kernel has no GRE support (module 'ip_gre'); install the GRE core first")
	}
	return nil
}

// Up brings the client tunnel up and returns its netdev.
//
// Idempotent by construction rather than by a guard: ensureGretun only recreates the device
// when an addressing-relevant attribute actually changed, address and MTU are applied with
// the *Replace forms, and the FOU/IPsec steps are all "make sure this exists". Calling Up on
// a healthy tunnel therefore touches nothing and returns the same name.
func (greOutDriver) Up(cfg VpnOutboundConfig) (string, error) {
	st, err := greOutParse(cfg)
	if err != nil {
		return "", err
	}
	remote, err := greOutResolve(st.Server)
	if err != nil {
		return "", err
	}
	local, err := greOutLocal(st)
	if err != nil {
		return "", err
	}
	inner, prefix, err := greOutInner(st.Address)
	if err != nil {
		return "", err
	}
	name := greOutIfName(cfg.Tag)
	gre := &GreService{}

	// ip_gre is loaded before any LinkAdd, and fou before any encap device: a FOU LinkAdd
	// against an unloaded module fails EINVAL rather than degrading to plain GRE.
	gre.runCmd("modprobe", greModule)
	if st.FouEnable {
		gre.runCmd("modprobe", greFouModule)
		if err := greOutEnsureFou(cfg.Tag, st.greOutFouPort()); err != nil {
			return "", err
		}
	} else {
		greOutStopFouKeeper(cfg.Tag)
	}

	want := &netlink.Gretun{
		Local:  local,
		Remote: remote,
		Ttl:    st.greOutTtl(),
		// Not decoration: a zero here DISABLES path-MTU discovery (see the file header).
		PMtuDisc: 1,
	}
	if st.FouEnable {
		want.EncapType = uint16(netlink.FOU)
		want.EncapDport = uint16(st.greOutFouPort())
		// "auto": the kernel picks the source port. Required when this host is the NATed
		// end, which is the whole reason to be speaking FOU at all.
		want.EncapSport = 0
	}
	if err := gre.ensureGretun(name, want, st.greOutMtu()); err != nil {
		return "", fmt.Errorf("gre outbound %s: %w", cfg.Tag, err)
	}

	if err := greOutSetAddr(name, inner, prefix); err != nil {
		return "", fmt.Errorf("gre outbound %s: %w", cfg.Tag, err)
	}

	if st.IpsecEnable {
		if err := greOutSyncIpsec(cfg.Tag, st, local, remote); err != nil {
			// Not fatal: the netdev exists and is the promise Up owes the framework, charon
			// keeps retrying on its own, and Status reports the SA as down. Failing here
			// instead would delete a tunnel that is one reachable responder away from
			// working.
			logger.Warning("gre outbound: IPsec setup for", cfg.Tag, "failed:", err)
		}
	} else {
		greOutRemoveIpsec(cfg.Tag)
	}
	return name, nil
}

// greOutSetAddr makes the device hold exactly the configured inner address. Foreign
// addresses are removed rather than left: a stale one from a previous config is a second
// candidate for source selection, and picking it sends packets the far side drops.
func greOutSetAddr(name string, ip net.IP, prefix int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	want := &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, 32)}}
	have, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return err
	}
	for _, a := range have {
		if a.IPNet != nil && a.IPNet.String() == want.IPNet.String() {
			continue
		}
		victim := a
		_ = netlink.AddrDel(link, &victim)
	}
	return netlink.AddrReplace(link, want)
}

// Down tears the tunnel back down. Tolerates being called on one that is already gone, which
// is what happens when the panel restarts between a failed Up and the next reconcile.
func (greOutDriver) Down(cfg VpnOutboundConfig) error {
	name := greOutIfName(cfg.Tag)
	greOutStopFouKeeper(cfg.Tag)
	greOutRemoveIpsec(cfg.Tag)

	if st, err := greOutParse(cfg); err == nil && st.FouEnable {
		// Unregistering is safe even if a GRE INBOUND happens to use the same port: its
		// reconcile runs ensureFouPort on every traffic tick and puts it straight back.
		_ = netlink.FouDel(netlink.Fou{
			Port:     st.greOutFouPort(),
			Protocol: unix.IPPROTO_GRE,
			Family:   unix.AF_INET,
		})
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // already gone
	}
	return netlink.LinkDel(link)
}

// Status reports what the panel needs to tell "configured" from "carrying traffic".
//
// A GRE device is up the moment it is created: there is no handshake, no keepalive and no
// session, so link state alone says almost nothing. The honest signals are the byte counters
// (the device counts what it has actually encapsulated and decapsulated), the IPsec SA when
// encryption is required, and the FOU registration when the far side is speaking UDP at us.
func (greOutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	name := greOutIfName(cfg.Tag)
	st, err := greOutParse(cfg)
	if err != nil {
		return false, err.Error()
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return false, "interface " + name + " is not present"
	}
	up := link.Attrs().Flags&net.FlagUp != 0
	parts := []string{name}
	if !up {
		parts = append(parts, "DOWN")
	}
	if g, ok := link.(*netlink.Gretun); ok {
		parts = append(parts, fmt.Sprintf("%s -> %s", g.Local, g.Remote))
	}
	if addrs, err := netlink.AddrList(link, unix.AF_INET); err == nil && len(addrs) > 0 {
		inner := "inner " + addrs[0].IPNet.String()
		if p := strings.TrimSpace(st.Peer); p != "" {
			// Shown so the operator has the address to ping when the counters say the tunnel
			// is carrying nothing, which is the question this panel cannot answer for them.
			inner += " -> " + p
		}
		parts = append(parts, inner)
	} else {
		// Without an address the kernel picks a source from another interface and the far
		// side has no route back, which looks exactly like a dead tunnel.
		up = false
		parts = append(parts, "NO INNER ADDRESS")
	}
	parts = append(parts, fmt.Sprintf("mtu %d", link.Attrs().MTU))
	if s := link.Attrs().Statistics; s != nil {
		parts = append(parts, fmt.Sprintf("rx %s, tx %s", greOutBytes(s.RxBytes), greOutBytes(s.TxBytes)))
	}

	if st.FouEnable {
		port := st.greOutFouPort()
		if greOutFouRegistered(port) {
			parts = append(parts, fmt.Sprintf("fou udp/%d", port))
		} else {
			// The GRE INBOUND service unregisters every FOU port it did not plan itself, on
			// every traffic tick. greOutEnsureFou runs a keeper against that; if the port is
			// still missing when someone looks, the keeper is not running (the panel was
			// restarted without this tunnel being raised), so say so rather than showing a
			// tunnel that can transmit and cannot receive.
			up = false
			parts = append(parts, fmt.Sprintf("FOU PORT udp/%d NOT REGISTERED (re-save this outbound)", port))
		}
	}
	if st.IpsecEnable {
		if ok, detail := greOutIpsecUp(cfg.Tag); ok {
			parts = append(parts, "ipsec "+detail)
		} else {
			// Required and not established means every packet we send is dropped by the far
			// side, so this is a down tunnel however healthy the netdev looks.
			up = false
			parts = append(parts, "IPSEC DOWN ("+detail+")")
		}
	}
	return up, strings.Join(parts, ", ")
}

func greOutBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// ---- FOU ---------------------------------------------------------------------------------

// A FOU receive port has to be registered for UDP-encapsulated GRE to arrive at all: the
// encap on the netdev only covers the TRANSMIT side. gre.go's ensureFouPort does the
// registration and is reused verbatim.
//
// The keeper exists because of a genuine conflict with the inbound side that cannot be fixed
// from here. GreService.applyPlan calls reconcileFouPorts on every traffic-job tick, and that
// function deletes every registered IPPROTO_GRE port that is not in the plan it just built
// from the inbounds table. An outbound tunnel's port is never in that plan, so it is swept
// away within one tick and the tunnel goes one-way: it keeps transmitting and stops
// receiving, which is the hardest kind of failure to see. Re-asserting the registration on a
// short ticker keeps the port present; FouAdd is a single netlink message and treats an
// existing port as success, so the cost is nothing. The real fix is for reconcileFouPorts to
// spare ports an outbound owns, which belongs in gre.go.
const greOutFouReassert = 2 * time.Second

// greOutFouKeep is one running keeper. The port is held next to the stop channel because a
// keeper is bound to the port it was started with: without it, changing an outbound's FOU port
// left the old keeper re-registering the OLD port for ever, and the new one was registered
// once by Up and then swept away for good.
type greOutFouKeep struct {
	port int
	stop chan struct{}
}

var (
	greOutFouMu     sync.Mutex
	greOutFouKeeper = map[string]*greOutFouKeep{} // tag -> keeper
)

// greOutEnsureFou registers the receive port, turns GRO off on the interface that will
// receive it, and starts the keeper. Idempotent: a second call for the same tag and port
// leaves the running keeper alone.
func greOutEnsureFou(tag string, port int) error {
	if err := ensureFouPort(port); err != nil {
		return fmt.Errorf("cannot register FOU receive port %d: %w", port, err)
	}
	// Not tuning, correctness. Coalesced UDP is not decapsulated back into the individual
	// GRE payloads, so nearly every segment is lost while a trickle survives: the tunnel
	// comes up, ping works, and any real transfer dies. It has to be off on the PHYSICAL
	// interface the packets arrive on, because the coalescing happens there, before anything
	// tunnel-shaped exists. Never turned back on: an operator who wants GRO has a reason, and
	// re-enabling it would silently break a working FOU tunnel.
	if iface, err := greWanIface(); err == nil {
		if err := (&GreService{}).runCmd("ethtool", "-K", iface, "gro", "off"); err != nil {
			logger.Warning("gre outbound: could not disable GRO on", iface,
				"- FOU traffic will see heavy loss until it is off:", err)
		}
	} else {
		logger.Warning("gre outbound: cannot find the WAN interface to disable GRO for FOU:", err)
	}

	greOutFouMu.Lock()
	defer greOutFouMu.Unlock()
	if k, running := greOutFouKeeper[tag]; running {
		if k.port == port {
			return nil
		}
		close(k.stop) // the port changed, so this keeper is now asserting the wrong one
		delete(greOutFouKeeper, tag)
	}
	stop := make(chan struct{})
	greOutFouKeeper[tag] = &greOutFouKeep{port: port, stop: stop}
	go func() {
		t := time.NewTicker(greOutFouReassert)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = ensureFouPort(port)
			}
		}
	}()
	return nil
}

func greOutStopFouKeeper(tag string) {
	greOutFouMu.Lock()
	defer greOutFouMu.Unlock()
	if k, ok := greOutFouKeeper[tag]; ok {
		close(k.stop)
		delete(greOutFouKeeper, tag)
	}
}

func greOutFouRegistered(port int) bool {
	have, err := netlink.FouList(unix.AF_INET)
	if err != nil {
		return false
	}
	for _, f := range have {
		if f.Port == port && f.Protocol == unix.IPPROTO_GRE {
			return true
		}
	}
	return false
}

// ---- GRE over IPsec ----------------------------------------------------------------------

// ESP TRANSPORT mode on the shared charon, the mirror image of greipsec.go. Transport, not
// tunnel: GRE already carries the encapsulation, so tunnel mode would add a second IP header
// for nothing and cost 20 more bytes of MTU. The one structural difference from the server
// side is that we INITIATE, so the connection carries local_addrs/remote_addrs and
// start_action rather than waiting to be called.
//
// syncCharon() is deliberately NOT used here, and the reason is an ORDERING one rather than
// anything about what it does. It asks charonNeeded() first and STOPS the daemon when the
// answer is no, and charonNeeded() reads the STORED tunnel list, but Save brings a tunnel up
// before it persists it (the interface name is decided by bringing it up). So the list does
// not yet contain the tunnel being configured, and calling syncCharon from inside Up would
// have the daemon stopped by the very save that is setting it up. The three steps it wraps
// (write the config, make sure charon is running, reload) are called directly instead, which
// is the half of syncCharon that applies to an initiator.
//
// charonNeeded() does otherwise account for this driver: vpnOutboundNeedsCharon has a
// VpnOutGre case reading ipsecEnable, so once a tunnel IS stored, an unrelated inbound save
// cannot stop the daemon under it. That is also what eventually collects the daemon this
// driver leaves running on teardown (see greOutRemoveIpsec).

func greOutIpsecConn(tag string) string {
	// Charon connection names share one namespace with the inbound side's "gre-<id>" and
	// "ikev2-<id>", so the prefix has to be distinct or a load would silently replace one.
	return "greout-" + greOutIfName(tag)
}

func greOutIpsecConfPath(tag string) string {
	return fmt.Sprintf("%s/%s.conf", swanctlConfDir, greOutIpsecConn(tag))
}

func greOutSyncIpsec(tag string, st *greOutSettings, local, remote net.IP) error {
	if err := greOutWriteIpsecConf(tag, st, local, remote); err != nil {
		return err
	}
	if err := writeCharonConf(); err != nil {
		return err
	}
	if err := ensureCharonRunning(); err != nil {
		return err
	}
	return reloadCharon()
}

func greOutWriteIpsecConf(tag string, st *greOutSettings, local, remote net.IP) error {
	esc := strings.ReplaceAll(st.IpsecPsk, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	conn := greOutIpsecConn(tag)
	localID := strings.TrimSpace(st.IpsecLocalId)
	if localID == "" {
		localID = local.String()
	}
	_ = os.MkdirAll(swanctlConfDir, 0755)
	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui GRE outbound (ESP transport, initiator) - do not edit\n")
	b.WriteString("connections {\n")
	b.WriteString(fmt.Sprintf("    %s {\n", conn))
	// 0 (the default when the operator says nothing) accepts either version as responder and
	// INITIATES with IKEv2, which is exactly what a client wants; 1 is there for the older
	// routers that only speak ISAKMP and would otherwise answer nothing at all.
	b.WriteString(fmt.Sprintf("        version = %d\n", st.IpsecIkeVersion))
	b.WriteString(fmt.Sprintf("        local_addrs = %s\n", local))
	b.WriteString(fmt.Sprintf("        remote_addrs = %s\n", remote))
	b.WriteString("        mobike = no\n")
	b.WriteString("        rekey_time = 3h\n")
	b.WriteString("        reauth_time = 0s\n")
	b.WriteString("        dpd_delay = 30s\n")
	b.WriteString("        fragmentation = yes\n")
	// The same wide list the responder side offers, for the same reason: the far side may be
	// a consumer router with a narrow, dated set, and a strict list shows up as
	// NO_PROPOSAL_CHOSEN with nothing else to go on.
	b.WriteString("        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256gcm16-prfsha256-ecp256,aes256-sha1-modp1536,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,default\n")
	b.WriteString(fmt.Sprintf("        local {\n            auth = psk\n            id = %s\n        }\n", localID))
	b.WriteString("        remote {\n            auth = psk\n")
	if id := strings.TrimSpace(st.IpsecRemoteId); id != "" {
		// A vpn-ui GRE inbound presents "gre-<id>.vpn-ui" and its recipe says to pin it.
		// Pinning is also what stops us accepting a PSK-authenticated stranger on the same
		// address.
		b.WriteString(fmt.Sprintf("            id = %s\n", id))
	}
	b.WriteString("        }\n")
	b.WriteString("        children {\n")
	b.WriteString("            gre {\n")
	b.WriteString("                mode = transport\n")
	// Narrowed to protocol 47 so nothing else leaving this host is swept into the SA, and
	// `dynamic` resolves to the address the SA actually lands on.
	b.WriteString("                local_ts = dynamic[gre]\n")
	b.WriteString("                remote_ts = dynamic[gre]\n")
	b.WriteString("                esp_proposals = aes256gcm16,aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1,default\n")
	b.WriteString("                rekey_time = 1h\n")
	// We are the initiator, so the SA is brought up on load and re-established whenever it
	// is lost. Without both of these a tunnel that drops once stays down until someone
	// re-saves it in the panel.
	b.WriteString("                start_action = start\n")
	b.WriteString("                close_action = start\n")
	b.WriteString("                dpd_action = restart\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	b.WriteString("secrets {\n")
	b.WriteString(fmt.Sprintf("    ike-%s {\n", conn))
	// TWO owners, both required. strongSwan matches a PSK by looking up an owner for BOTH
	// ends, so a secret that lists owners must match `me` AND `other`; only an owner-less
	// secret is a full wildcard. Naming our identity plus %any matches this pair while still
	// beating any owner-less key on specificity, which is what stops charon signing with
	// L2TP's key and the peer answering "MAC mismatched". Same shape greipsec.go arrived at.
	b.WriteString(fmt.Sprintf("        id_local = %s\n", localID))
	b.WriteString("        id_any = %any\n")
	b.WriteString(fmt.Sprintf("        secret = \"%s\"\n", esc))
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return os.WriteFile(greOutIpsecConfPath(tag), []byte(b.String()), 0600)
}

// greOutRemoveIpsec drops the connection and its key, then reloads so charon stops offering
// them. Silent when there was nothing to remove, which is the common case.
func greOutRemoveIpsec(tag string) {
	path := greOutIpsecConfPath(tag)
	if _, err := os.Stat(path); err != nil {
		return
	}
	_ = os.Remove(path)
	_ = exec.Command(swanctlBin(), "--terminate", "--ike", greOutIpsecConn(tag)).Run()
	// Reload rather than syncCharon, for the ordering reason above and because Down is called
	// from three places (delete, save-disabled, shutdown) that persist at different points, so
	// "does anything still need charon" is not a question this can ask reliably. The daemon is
	// therefore left running even when nothing else wants it, which is the safe direction to
	// err in and no longer permanent: charonNeeded now counts GRE outbounds, so the next
	// inbound-driven syncCharon collects it once the stored list no longer names this tunnel.
	_ = reloadCharon()
}

// greOutIpsecUp reports whether this tunnel's child SA is installed, by connection name.
// swanctl prints one block per IKE_SA headed by "<connection>: #<id>, ESTABLISHED, ...", and
// the child lines beneath it are indented, so a prefix match on the raw line identifies the
// block without the sub-line ambiguity ikev2.go documents.
func greOutIpsecUp(tag string) (bool, string) {
	if !procMgr.IsRunning(ikev2ProcName) {
		return false, "charon is not running"
	}
	out, err := exec.Command(swanctlBin(), "--list-sas").CombinedOutput()
	if err != nil {
		return false, "cannot query charon"
	}
	conn := greOutIpsecConn(tag)
	inBlock, sawIke := false, false
	for _, ln := range strings.Split(string(out), "\n") {
		if ln == "" {
			continue
		}
		if ln[0] != ' ' && ln[0] != '\t' {
			inBlock = strings.HasPrefix(ln, conn+":")
			sawIke = sawIke || inBlock
			continue
		}
		// Only the child SA carries the traffic. An IKE SA on its own means the two ends
		// authenticated and then failed to agree on a child, which from the data plane's
		// point of view is the same as no IPsec at all.
		if inBlock && strings.Contains(ln, "INSTALLED") {
			return true, "child SA installed"
		}
	}
	if sawIke {
		return false, "IKE SA up but no child SA installed"
	}
	return false, "no SA"
}
