package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuard as an OUTBOUND: the panel is the CLIENT of somebody else's WireGuard
// server. The mirror image of wgc.go, and much the smaller half of the protocol,
// because WireGuard is symmetric: there is no address assignment, no session
// negotiation and no auth round trip, so a client is just a device holding our
// private key and exactly ONE peer (the remote server) whose AllowedIPs claim the
// whole address space.
//
// This file also carries the client-side plumbing shared with vpnout_awg.go
// (interface naming, address parsing, link creation, the IPv6 egress rule). Those
// helpers are named vpnOut* and are deliberately typed in stdlib/netlink terms
// only: the two drivers talk to DIFFERENT wgctrl forks whose Key/Config/Device
// types are unrelated, so anything touching those types has to be written twice.
// Same split wgc.go and awg.go already live with.

const (
	// vpnOutWgIfacePrefix names the client-side WireGuard links, vpnOutAwgIfacePrefix
	// the AmneziaWG ones. Both are deliberately NOT the obvious "wgc.../awg..." with
	// a suffix, and that is load-bearing rather than cosmetic:
	//
	// the server-side reconcilers garbage-collect the links they own, and a client
	// link that looks like one of theirs is claimed by no inbound and would be
	// DELETED out from under a working outbound on the next traffic tick.
	// AnyInterfaceUp() applies the same test and would likewise report a client
	// tunnel as a live server data plane.
	//
	// The ownership test is now an anchored NAME SHAPE plus a link-type check plus
	// the ownership manifest (ifaceown.go), not the bare prefix scan it used to be,
	// and "wgo123"/"awo123" match neither `^wgc[0-9]+$` nor `^awg[0-9]+$`. They were
	// already safe under the old prefix rule too ('o' is not a digit and the prefixes
	// differ at byte 3), so the two namespaces cannot overlap either way. Keep any new
	// client-side prefix outside those shapes, and add a case to ifaceown_test.go's
	// ours-vs-theirs table.
	vpnOutWgIfacePrefix  = "wgo"
	vpnOutAwgIfacePrefix = "awo"

	// vpnOutKeyLen is the byte length of a Curve25519 WireGuard key.
	vpnOutKeyLen = 32

	// vpnOutMinMTU/vpnOutMaxMTU bound a sane tunnel MTU, and vpnOutMinV6MTU is the
	// IPv6 minimum link MTU. The v6 one is a hard kernel rule rather than taste: it
	// answers EINVAL to an address add on a link below 1280, so a v6 tunnel
	// configured under it fails at address assignment with nothing naming the MTU.
	vpnOutMinMTU   = 576
	vpnOutMaxMTU   = 9000
	vpnOutMinV6MTU = 1280

	// vpnOutDefaultKeepalive is the persistent-keepalive used when the operator did
	// not choose one. A client is almost always the NATed side, and without keepalive
	// the server's return path dies as soon as the NAT mapping expires (the tunnel
	// then looks "up" while nothing comes back). 25s is the WireGuard-recommended
	// value, below every common NAT timeout.
	vpnOutDefaultKeepalive = 25 * time.Second
)

// wgOutSettings is the WireGuard slice of a VpnOutboundConfig.Settings blob. Every
// field is what the REMOTE operator handed us; nothing here is generated locally,
// which is the whole difference from wgcSettings (where the panel mints the keys).
type wgOutSettings struct {
	// PrivateKey is OUR key on their server. They hold the matching public key.
	PrivateKey string `json:"privateKey"`
	// PeerPublicKey is the remote SERVER's public key, from its [Peer] block.
	PeerPublicKey string `json:"peerPublicKey"`
	// PresharedKey is optional and must match the server's, when it uses one.
	PresharedKey string `json:"presharedKey"`
	// Endpoint is the server's host:port. A name is resolved at Up (see below).
	Endpoint string `json:"endpoint"`
	// Address is the tunnel address THEY assigned us, as one or more CIDRs. Accepts
	// the comma-separated form of a .conf [Interface] Address line so an operator can
	// paste it verbatim.
	Address string `json:"address"`
	Mtu     int    `json:"mtu"`
	// Keepalive is in seconds. A pointer so "absent" (use the default) stays
	// distinguishable from an explicit 0 (turn keepalive off), the same reason
	// userLimit is a *int elsewhere in this package.
	Keepalive *int `json:"keepalive"`
}

func (o *wgOutSettings) mtu() int {
	if o.Mtu > 0 {
		return o.Mtu
	}
	return wgDefaultMTU
}

func (o *wgOutSettings) keepalive() time.Duration {
	if o.Keepalive == nil {
		return vpnOutDefaultKeepalive
	}
	if *o.Keepalive <= 0 {
		return 0
	}
	return time.Duration(*o.Keepalive) * time.Second
}

// wgOutDriver is the registered "wireguard" outbound driver.
//
// lastEndpoint remembers the endpoint we last pushed per interface, and exists to
// keep Up idempotent against a ROAMING server: the kernel rewrites a peer's stored
// endpoint whenever a valid handshake arrives from a different source address, so
// comparing the device's endpoint against the configured one would see a difference
// that we did not cause and re-push it on every reconcile, tearing down a working
// session each time. Comparing against what we last applied only re-pushes when the
// operator edited the endpoint or its name resolved somewhere new. Same shape as
// AwgService.lastObfs.
type wgOutDriver struct {
	mu           sync.Mutex
	lastEndpoint map[string]string
}

var wgOutInstance = &wgOutDriver{}

// Asserted rather than left to duck typing. VpnOutSecrets is optional, so a typo in
// the method name would not fail the build: it would just quietly stop matching, and
// List would go back to shipping private keys to the browser while still looking
// masked. That is the exact failure the interface exists to prevent, so it is worth a
// compile-time check.
var (
	_ VpnOutDriver  = (*wgOutDriver)(nil)
	_ VpnOutSecrets = (*wgOutDriver)(nil)
)

func init() { RegisterVpnOutDriver(VpnOutWireguard, wgOutInstance) }

// SecretKeys names the settings keys that must never reach the panel.
//
// Only the two that are credentials. The private key is our identity on the remote
// server, and the preshared key is the second factor mixed into the handshake;
// neither is recoverable from anything else in the blob.
//
// peerPublicKey and endpoint are deliberately absent: a public key is public by
// construction, the endpoint is where the operator pointed this tunnel, and both are
// the first things anyone checks when a tunnel will not handshake. Masking them would
// cost real diagnosis for no secrecy. Nothing here is a pasted profile blob either,
// since every field is discrete, so there is no key hiding a private key inside a
// larger string.
func (d *wgOutDriver) SecretKeys() []string {
	return []string{"privateKey", "presharedKey"}
}

func (d *wgOutDriver) settings(cfg VpnOutboundConfig) (*wgOutSettings, error) {
	st := &wgOutSettings{}
	if len(cfg.Settings) == 0 {
		return st, errors.New("this WireGuard outbound has no settings")
	}
	if err := json.Unmarshal([]byte(cfg.Settings), st); err != nil {
		return st, fmt.Errorf("bad WireGuard outbound settings: %w", err)
	}
	return st, nil
}

// iface is the deterministic link name for this outbound.
func (d *wgOutDriver) iface(cfg VpnOutboundConfig) string {
	return vpnOutIfaceName(vpnOutWgIfacePrefix, cfg.Tag)
}

// ServerHost names what the outer UDP goes to, so this tunnel can be carried inside
// another. The endpoint's port is dropped by the framework: a rule selects on the
// address alone.
func (d *wgOutDriver) ServerHost(cfg VpnOutboundConfig) (string, error) {
	st, err := d.settings(cfg)
	if err != nil {
		return "", err
	}
	return st.Endpoint, nil
}

// Validate rejects a config before anything is brought up. Key material and the
// endpoint shape are checked here rather than at Up so the operator is told what is
// wrong while the modal is still open, instead of getting a netlink errno later.
func (d *wgOutDriver) Validate(cfg VpnOutboundConfig) error {
	st, err := d.settings(cfg)
	if err != nil {
		return err
	}
	return st.validate()
}

func (o *wgOutSettings) validate() error {
	if err := vpnOutCheckKey("private key", o.PrivateKey); err != nil {
		return err
	}
	if err := vpnOutCheckKey("peer public key", o.PeerPublicKey); err != nil {
		return err
	}
	if strings.TrimSpace(o.PresharedKey) != "" {
		if err := vpnOutCheckKey("preshared key", o.PresharedKey); err != nil {
			return err
		}
	}
	if err := vpnOutCheckEndpoint(o.Endpoint); err != nil {
		return err
	}
	addrs, err := vpnOutParseAddrs(o.Address)
	if err != nil {
		return err
	}
	return vpnOutCheckMTUKeepalive(o.Mtu, o.Keepalive, addrs)
}

// Up brings the client tunnel up and returns its interface name.
//
// Idempotent: an existing link is reused rather than recreated, its addresses are
// reconciled in place (a replace of an identical address does not disturb traffic),
// and the MTU is only set when it differs. What matters most is that the peer is
// re-pushed ONLY when something the operator controls actually changed, so a
// steady-state call issues no ConfigureDevice and the live crypto session, with its
// handshake clock and counters, survives every reconcile untouched.
func (d *wgOutDriver) Up(cfg VpnOutboundConfig) (string, error) {
	st, err := d.settings(cfg)
	if err != nil {
		return "", err
	}
	if err := st.validate(); err != nil {
		return "", err
	}
	priv, err := wgtypes.ParseKey(strings.TrimSpace(st.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	peerPub, err := wgtypes.ParseKey(strings.TrimSpace(st.PeerPublicKey))
	if err != nil {
		return "", fmt.Errorf("peer public key: %w", err)
	}
	var psk *wgtypes.Key
	if s := strings.TrimSpace(st.PresharedKey); s != "" {
		k, err := wgtypes.ParseKey(s)
		if err != nil {
			return "", fmt.Errorf("preshared key: %w", err)
		}
		psk = &k
	}
	addrs, err := vpnOutParseAddrs(st.Address)
	if err != nil {
		return "", err
	}
	// Resolved at every Up rather than once at save: a name is how consumer-grade
	// remote servers are usually addressed, and the reconciler calling Up again is
	// the only thing that ever moves the peer to the host's new address.
	endpoint, err := net.ResolveUDPAddr("udp", strings.TrimSpace(st.Endpoint))
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", st.Endpoint, err)
	}

	iface := d.iface(cfg)
	// Only the device itself is built here. Egress routing (the private table and the
	// oif rule that make a pinned socket able to send) belongs to the framework, which
	// installs it around Up for every protocol: see vpnOutBindEgress in vpnoutbound.go.
	err = vpnOutEnsureLink(iface, st.mtu(), addrs, func(la netlink.LinkAttrs) netlink.Link {
		return &netlink.Wireguard{LinkAttrs: la}
	})
	if err != nil {
		if isNotSupported(err) {
			return "", fmt.Errorf("wireguard kernel module unavailable (install/modprobe wireguard): %w", err)
		}
		return "", err
	}

	cl, err := wgctrl.New()
	if err != nil {
		return "", fmt.Errorf("wgctrl: %w", err)
	}
	defer cl.Close()

	if err := d.configure(cl, iface, priv, peerPub, psk, endpoint, st.keepalive(), vpnOutHasV6(addrs)); err != nil {
		return "", fmt.Errorf("configuring %s: %w", iface, err)
	}
	return iface, nil
}

// configure reconciles the device to exactly one peer (the remote server), touching
// the kernel only when something differs.
//
// AllowedIPs is the full space because this is a full-tunnel client: on the client
// side AllowedIPs is a cryptokey ROUTING table, i.e. "which destinations may this
// peer carry", not a grant of anything to the server. ::/0 is added only when a v6
// tunnel address exists, matching the v4-only default the inbound side uses to avoid
// an IPv6 leak.
func (d *wgOutDriver) configure(cl *wgctrl.Client, iface string, priv, peerPub wgtypes.Key,
	psk *wgtypes.Key, endpoint *net.UDPAddr, keepalive time.Duration, withV6 bool) error {

	dev, derr := cl.Device(iface)
	var cur *wgtypes.Peer
	if derr == nil && dev != nil {
		for i := range dev.Peers {
			if dev.Peers[i].PublicKey == peerPub {
				cur = &dev.Peers[i]
				break
			}
		}
	}

	allowed := vpnOutAllowedIPs(withV6)
	peer := wgtypes.PeerConfig{
		PublicKey:                   peerPub,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  allowed,
		PersistentKeepaliveInterval: &keepalive,
	}
	if psk != nil {
		peer.PresharedKey = psk
	} else {
		// An all-zero key is how the kernel spells "no preshared key", so clearing a
		// PSK the operator removed needs an explicit zero rather than a nil (which
		// means "leave it alone").
		var zero wgtypes.Key
		peer.PresharedKey = &zero
	}

	// The private key is compared through its PUBLIC half: an unprivileged read
	// returns a masked private key, and wgc.go's reconcilePeers already learned that
	// re-setting an identical private key can reset live sessions.
	needKey := derr != nil || dev == nil || dev.PublicKey != priv.PublicKey()
	pushPeer := needKey || cur == nil ||
		allowedIPsKey(cur.AllowedIPs) != allowedIPsKey(allowed) ||
		cur.PersistentKeepaliveInterval != keepalive ||
		cur.PresharedKey != *peer.PresharedKey

	// The endpoint is compared against what WE last pushed, not against the device:
	// see the lastEndpoint comment on wgOutDriver.
	if cur == nil || cur.Endpoint == nil || d.endpointChanged(iface, endpoint.String()) {
		peer.Endpoint = endpoint
		pushPeer = true
	}

	var ops []wgtypes.PeerConfig
	if pushPeer {
		ops = append(ops, peer)
	}
	// A client device has exactly one peer. Anything else is left over from an edit
	// that changed the server's key, and would keep a route into a server we no
	// longer trust.
	if dev != nil {
		for _, p := range dev.Peers {
			if p.PublicKey != peerPub {
				ops = append(ops, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
			}
		}
	}
	if !needKey && len(ops) == 0 {
		return nil // steady state: do not disturb the live session
	}

	// ListenPort is deliberately left unset. A client dials out, so the kernel's
	// ephemeral port is correct, and pinning one risks colliding with a wg-c INBOUND
	// listening on this same host.
	//
	// No FwMark either, which wg-quick DOES need: it puts its default route in the
	// main table and then has to except the tunnel's own encrypted packets from it.
	// Here the default route lives in a private table reached only by an `oif` rule
	// (vpnOutBindEgress), and WireGuard's UDP socket is not bound to the wg device, so
	// its flow carries no oif, misses the rule, and routes over the host's normal path.
	// The loop that fwmark exists to break cannot form.
	wcfg := wgtypes.Config{ReplacePeers: false, Peers: ops}
	if needKey {
		wcfg.PrivateKey = &priv
	}
	if err := cl.ConfigureDevice(iface, wcfg); err != nil {
		return err
	}
	d.rememberEndpoint(iface, endpoint.String())
	return nil
}

// Down removes the tunnel. Tolerates an already-absent link, which is the normal
// state after a panel restart that followed a failed Up.
func (d *wgOutDriver) Down(cfg VpnOutboundConfig) error {
	iface := d.iface(cfg)
	err := vpnOutDeleteLink(iface, vpnOutWgIfacePrefix)
	// An interface recorded under an older naming scheme still has to be cleaned up,
	// or it stays up forever carrying traffic nothing tracks.
	if prev := strings.TrimSpace(cfg.Iface); prev != "" && prev != iface {
		if perr := vpnOutDeleteLink(prev, vpnOutWgIfacePrefix); err == nil {
			err = perr
		}
	}
	d.forgetEndpoint(iface)
	return err
}

// Status reports liveness from the last handshake, which is the only honest signal
// WireGuard offers: the link is "up" the moment it is created, and a peer with the
// wrong key or an unreachable endpoint looks exactly like a working one until you
// look at the handshake clock.
func (d *wgOutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	st, err := d.settings(cfg)
	if err != nil {
		return false, err.Error()
	}
	iface := d.iface(cfg)
	if _, err := netlink.LinkByName(iface); err != nil {
		return false, "interface " + iface + " does not exist"
	}
	cl, err := wgctrl.New()
	if err != nil {
		return false, "wgctrl: " + err.Error()
	}
	defer cl.Close()

	dev, err := cl.Device(iface)
	if err != nil {
		return false, iface + ": " + err.Error()
	}
	peerPub, err := wgtypes.ParseKey(strings.TrimSpace(st.PeerPublicKey))
	if err != nil {
		return false, "peer public key: " + err.Error()
	}
	for _, p := range dev.Peers {
		if p.PublicKey != peerPub {
			continue
		}
		return vpnOutStatusDetail(iface, vpnOutEndpointText(p.Endpoint, st.Endpoint),
			p.LastHandshakeTime, p.ReceiveBytes, p.TransmitBytes)
	}
	return false, iface + ": the server is not configured as a peer (re-save this outbound)"
}

func (d *wgOutDriver) endpointChanged(iface, endpoint string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastEndpoint[iface] != endpoint
}

func (d *wgOutDriver) rememberEndpoint(iface, endpoint string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lastEndpoint == nil {
		d.lastEndpoint = make(map[string]string)
	}
	d.lastEndpoint[iface] = endpoint
}

func (d *wgOutDriver) forgetEndpoint(iface string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.lastEndpoint, iface)
}

// ---- client-side plumbing shared with vpnout_awg.go ------------------------------

// vpnOutIfaceName derives a bounded, deterministic link name from an outbound tag.
//
// The tag cannot be used raw: IFNAMSIZ caps a name at 15 bytes plus the NUL, and a
// tag is free text that may hold spaces or slashes. Hashing gives a fixed 8 hex
// digits, so the name is 11 bytes with room to spare, is stable across restarts
// (Down must be able to find what Up created without consulting state), and changes
// only when the tag does. A hash collision would have two outbounds share one
// device; at 32 bits over the handful of tunnels one panel holds that is far below
// the noise floor, and the deterministic name is worth more than the residual risk.
func vpnOutIfaceName(prefix, tag string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tag))
	return fmt.Sprintf("%s%08x", prefix, h.Sum32())
}

// vpnOutCheckKey rejects anything that is not a 32 byte base64 key. Written against
// the raw string rather than a wgtypes.ParseKey so both drivers can share it: they
// speak to different wgctrl forks whose Key types are unrelated.
func vpnOutCheckKey(field, s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("%s is not valid base64: %w", field, err)
	}
	if len(raw) != vpnOutKeyLen {
		return fmt.Errorf("%s decodes to %d bytes, a WireGuard key is %d", field, len(raw), vpnOutKeyLen)
	}
	return nil
}

// vpnOutCheckEndpoint checks the SHAPE of a host:port endpoint.
//
// Deliberately does not resolve it: Validate runs while the operator is still in the
// modal, so a DNS lookup would block the save behind a timeout, and a name that is
// not resolvable yet (split-horizon, a peer about to be provisioned) is not a reason
// to refuse the config. Resolution failure surfaces at Up, where it is a live error
// the operator can retry.
func vpnOutCheckEndpoint(ep string) error {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return errors.New("endpoint is required (the remote server's host:port)")
	}
	host, portStr, err := net.SplitHostPort(ep)
	if err != nil {
		return fmt.Errorf("endpoint %q must be host:port: %w", ep, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("endpoint %q has no host", ep)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("endpoint %q has an invalid port", ep)
	}
	return nil
}

// vpnOutCheckMTUKeepalive bounds the two numeric knobs both drivers share.
func vpnOutCheckMTUKeepalive(mtu int, keepalive *int, addrs []*netlink.Addr) error {
	if mtu != 0 && (mtu < vpnOutMinMTU || mtu > vpnOutMaxMTU) {
		return fmt.Errorf("mtu %d is out of range (%d-%d, leave it empty for %d)",
			mtu, vpnOutMinMTU, vpnOutMaxMTU, wgDefaultMTU)
	}
	if mtu != 0 && mtu < vpnOutMinV6MTU && vpnOutHasV6(addrs) {
		return fmt.Errorf("mtu %d is below the IPv6 minimum of %d and this tunnel has an IPv6 address, "+
			"which the kernel would refuse to assign", mtu, vpnOutMinV6MTU)
	}
	if keepalive != nil && (*keepalive < 0 || *keepalive > 65535) {
		return fmt.Errorf("keepalive %d is out of range (0-65535 seconds, 0 turns it off)", *keepalive)
	}
	return nil
}

// vpnOutParseAddrs parses the tunnel address(es) the remote operator assigned us.
// Accepts the comma-separated form of a .conf [Interface] Address line so it can be
// pasted verbatim, and a bare IP (which that file format allows), read as a single
// host address.
func vpnOutParseAddrs(spec string) ([]*netlink.Addr, error) {
	var out []*netlink.Addr
	for _, part := range strings.Split(spec, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			ip := net.ParseIP(p)
			if ip == nil {
				return nil, fmt.Errorf("address %q is not an IP address", p)
			}
			if ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		addr, err := netlink.ParseAddr(p)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", strings.TrimSpace(part), err)
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, errors.New("address is required (the tunnel address the remote server assigned)")
	}
	return out, nil
}

// vpnOutHasV6 reports whether any assigned tunnel address is IPv6.
func vpnOutHasV6(addrs []*netlink.Addr) bool {
	for _, a := range addrs {
		if a.IP.To4() == nil {
			return true
		}
	}
	return false
}

// vpnOutAllowedIPs is the full-tunnel cryptokey routing table for the one server peer.
func vpnOutAllowedIPs(withV6 bool) []net.IPNet {
	_, v4, _ := net.ParseCIDR("0.0.0.0/0")
	out := []net.IPNet{*v4}
	if withV6 {
		_, v6, _ := net.ParseCIDR("::/0")
		out = append(out, *v6)
	}
	return out
}

// vpnOutEnsureLink makes sure iface exists (created via mk when absent), carries
// exactly addrs, has the requested MTU and is up. Returns the link so the caller can
// hang routes off it.
func vpnOutEnsureLink(iface string, mtu int, addrs []*netlink.Addr, mk func(netlink.LinkAttrs) netlink.Link) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = iface
		if mtu > 0 {
			la.MTU = mtu
		}
		if addErr := netlink.LinkAdd(mk(la)); addErr != nil {
			return addErr
		}
		if link, err = netlink.LinkByName(iface); err != nil {
			return err
		}
	} else if mtu > 0 && link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			logger.Warningf("vpn outbound: could not set MTU %d on %s: %v", mtu, iface, err)
		}
	}
	if err := vpnOutSyncAddrs(link, addrs); err != nil {
		return err
	}
	// The address carries its own on-link route (a /24 gives the kernel a connected
	// route for the tunnel subnet, a /32 gives none), which is all the driver installs.
	return netlink.LinkSetUp(link)
}

// vpnOutSyncAddrs makes the link's addresses exactly want: it removes any address we
// did not ask for (an operator who edits the tunnel address must not be left with
// the old one still answering) and adds the ones missing.
func vpnOutSyncAddrs(link netlink.Link, want []*netlink.Addr) error {
	wanted := make(map[string]bool, len(want))
	for _, a := range want {
		wanted[a.IPNet.String()] = true
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		cur, err := netlink.AddrList(link, family)
		if err != nil {
			continue
		}
		for i := range cur {
			if cur[i].IPNet == nil || wanted[cur[i].IPNet.String()] {
				continue
			}
			// The v6 link-local belongs to the kernel: removing it breaks neighbour
			// discovery on the device and it is reinstated anyway.
			if cur[i].IP.IsLinkLocalUnicast() {
				continue
			}
			if err := netlink.AddrDel(link, &cur[i]); err != nil {
				logger.Debugf("vpn outbound: could not remove stale address %s from %s: %v",
					cur[i].IPNet, link.Attrs().Name, err)
			}
		}
	}
	for _, a := range want {
		if err := netlink.AddrReplace(link, a); err != nil {
			return fmt.Errorf("could not assign %s to %s: %w", a.IPNet, link.Attrs().Name, err)
		}
	}
	return nil
}

// vpnOutDeleteLink removes a client tunnel device, refusing any name outside the
// client namespace.
//
// The prefix check is not paranoia about our own code: the name can arrive from the
// stored Iface field, which a hand-edited or half-migrated settings row could point
// at anything, and deleting a link named there without checking would happily take
// out the host's own NIC. It also keeps this off the server-side wgc*/awg* links.
func vpnOutDeleteLink(iface, prefix string) error {
	if iface == "" || !strings.HasPrefix(iface, prefix) {
		return nil
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil // already gone, which is a valid outcome for Down
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("could not remove %s: %w", iface, err)
	}
	return nil
}

// vpnOutEndpointText prefers the endpoint the kernel currently holds (which shows
// where the server actually answered from after roaming) and falls back to the
// configured one before the first handshake.
func vpnOutEndpointText(live *net.UDPAddr, configured string) string {
	if live != nil {
		return live.String()
	}
	return strings.TrimSpace(configured)
}

// vpnOutStatusDetail renders the panel's one-line status from a peer's handshake
// clock and counters. Takes primitives so both drivers share it across their two
// incompatible wgtypes packages.
//
// wgHandshakeStale (the inbound side's liveness window) is reused deliberately:
// WireGuard rekeys about every 2 minutes under traffic, so a peer quiet for longer
// than that has stopped carrying anything, whichever side of the tunnel we are on.
func vpnOutStatusDetail(iface, endpoint string, handshake time.Time, rx, tx int64) (bool, string) {
	if handshake.IsZero() {
		return false, fmt.Sprintf("%s: no handshake with %s yet", iface, endpoint)
	}
	age := time.Since(handshake).Truncate(time.Second)
	up := age <= wgHandshakeStale
	state := "stale"
	if up {
		state = "connected"
	}
	return up, fmt.Sprintf("%s: %s to %s, last handshake %s ago, rx %s / tx %s",
		iface, state, endpoint, age, common.FormatTraffic(rx), common.FormatTraffic(tx))
}
