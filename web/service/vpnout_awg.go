package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	wgctrl "github.com/Jipok/wgctrl-go"
	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/vishvananda/netlink"
)

// AmneziaWG as an OUTBOUND: the panel is the CLIENT of somebody else's AmneziaWG
// server. Sibling of vpnout_wireguard.go exactly as awg.go is a sibling of wgc.go,
// and it reuses that file's client-side plumbing (vpnOutIfaceName, vpnOutParseAddrs,
// vpnOutEnsureLink, the IPv6 egress rule) plus awg.go's awgObfs type. What cannot be
// shared is anything typed in wgtypes: this driver speaks to the AmneziaWG-aware
// wgctrl FORK, whose Key/Config/Device types are unrelated to upstream's, so the
// device reconcile is written out a second time rather than abstracted.
//
// Two things differ from the WireGuard driver:
//
//  1. The link kind is "amneziawg", an out-of-tree module this panel DKMS-builds
//     (amneziawg_dkms.go). It is the one protocol here that can be unavailable on an
//     otherwise healthy host, so Up says why rather than returning a bare errno.
//  2. The obfuscation parameters are the client's half of the AWG 1.0 handshake
//     disguise and must MATCH the remote server (except Jc/Jmin/Jmax, the junk
//     counts, which are per-peer). They are copied from the config the remote
//     operator issued; nothing here is generated locally.

// awgOutSettings is the AmneziaWG slice of a VpnOutboundConfig.Settings blob: the
// WireGuard client fields plus the AWG 1.0 obfuscation set. JSON names match
// awgSettings so a server-side config and a client-side one read the same way.
type awgOutSettings struct {
	PrivateKey    string `json:"privateKey"`
	PeerPublicKey string `json:"peerPublicKey"`
	PresharedKey  string `json:"presharedKey"`
	Endpoint      string `json:"endpoint"`
	Address       string `json:"address"`
	Mtu           int    `json:"mtu"`
	Keepalive     *int   `json:"keepalive"`

	// AWG 1.0 obfuscation, taken verbatim from the server's issued config. Pointers
	// so "the operator left it blank" stays distinguishable from an explicit 0.
	Jc   *int   `json:"jc"`
	Jmin *int   `json:"jmin"`
	Jmax *int   `json:"jmax"`
	S1   *int   `json:"s1"`
	S2   *int   `json:"s2"`
	H1   string `json:"h1"`
	H2   string `json:"h2"`
	H3   string `json:"h3"`
	H4   string `json:"h4"`
}

func (o *awgOutSettings) mtu() int {
	if o.Mtu > 0 {
		return o.Mtu
	}
	return wgDefaultMTU
}

func (o *awgOutSettings) keepalive() time.Duration {
	if o.Keepalive == nil {
		return vpnOutDefaultKeepalive
	}
	if *o.Keepalive <= 0 {
		return 0
	}
	return time.Duration(*o.Keepalive) * time.Second
}

// obfs resolves the obfuscation set, defaulting every unset parameter to ZERO.
//
// This is the one place the client must NOT copy awgSettings.resolveObfs(), which
// fills in the recommended server-side defaults (4/8/80/77/90). Those defaults are a
// sensible thing to INVENT when standing up a server, and exactly the wrong thing to
// assume about somebody else's: junk and padding sizes that do not match theirs
// produce a handshake the far end silently drops, and the tunnel just never comes up
// with nothing in any log to say why. Zeroes reproduce plain WireGuard framing,
// which is what an AmneziaWG server with no obfuscation configured expects, so an
// operator who leaves these blank gets the behaviour their blank config describes.
// Empty H1-H4 are likewise left unapplied (awgObfs.apply skips them), which the
// module reads as the standard message types 1-4.
func (o *awgOutSettings) obfs() awgObfs {
	pick := func(p *int) int {
		if p != nil {
			return *p
		}
		return 0
	}
	return awgObfs{
		Jc: pick(o.Jc), Jmin: pick(o.Jmin), Jmax: pick(o.Jmax),
		S1: pick(o.S1), S2: pick(o.S2),
		H1: strings.TrimSpace(o.H1), H2: strings.TrimSpace(o.H2),
		H3: strings.TrimSpace(o.H3), H4: strings.TrimSpace(o.H4),
	}
}

// awgOutDriver is the registered "awg" outbound driver. lastApplied remembers the
// endpoint + obfuscation signature we last pushed per interface; see the
// wgOutDriver.lastEndpoint comment for why the endpoint cannot be compared against
// the device itself, and AwgService.lastObfs for the obfuscation half (the kernel
// does not report those parameters back, so a change is only detectable by
// remembering what we sent).
type awgOutDriver struct {
	mu          sync.Mutex
	lastApplied map[string]string
}

var awgOutInstance = &awgOutDriver{}

// See the same assertion in vpnout_wireguard.go: VpnOutSecrets is optional, so only
// the compiler can catch a method that stopped matching it.
var (
	_ VpnOutDriver       = (*awgOutDriver)(nil)
	_ VpnOutSecrets      = (*awgOutDriver)(nil)
	_ VpnOutAvailability = (*awgOutDriver)(nil)
)

func init() { RegisterVpnOutDriver(VpnOutAmneziaWG, awgOutInstance) }

// SecretKeys names the settings keys that must never reach the panel: the same two
// credentials as the WireGuard driver, and for the same reasons.
//
// The obfuscation parameters (jc, jmin, jmax, s1, s2, h1-h4) are deliberately NOT
// listed, which is a judgement call worth stating. They are sensitive in the sense
// that they are what makes this tunnel not look like WireGuard to a censor, so
// leaking them publicly would help fingerprint the far end. But they are not
// credentials: knowing them gets nobody a tunnel without a key the server has
// registered. Against that, they are shared configuration that has to MATCH the
// remote server exactly, and comparing them against the config the remote operator
// issued is the first step in diagnosing an AmneziaWG tunnel that will not
// handshake. Masking them would blank that whole section of the form and leave the
// operator unable to check or correct the one thing most likely to be wrong.
func (d *awgOutDriver) SecretKeys() []string {
	return []string{"privateKey", "presharedKey"}
}

// Available reports whether the out-of-tree amneziawg module can be used here.
//
// This is the ONLY kind in the outbound set whose missing requirement an operator can
// install from the panel: every other driver depends on a binary that is either
// embedded in this build or not (see backend/clients.go), while this module is
// DKMS-built by the AmneziaWG core's setup run. So the reason has to send them there
// rather than state the absence, and awgOutUnavailableReason already separates the
// host that has simply never built it from the one that never can.
//
// Checked up front rather than left to Up, unlike the WireGuard twin: wireguard is in
// every mainstream kernel since 5.6, so probing it up front risks a false negative
// that would refuse a working tunnel, whereas an amneziawg module is absent on every
// host that has not deliberately built one.
func (d *awgOutDriver) Available() (bool, string) {
	if moduleAvailable(amneziawgModule) {
		return true, ""
	}
	return false, "the amneziawg kernel module is not built for this kernel: " + awgOutUnavailableReason()
}

func (d *awgOutDriver) settings(cfg VpnOutboundConfig) (*awgOutSettings, error) {
	st := &awgOutSettings{}
	if len(cfg.Settings) == 0 {
		return st, errors.New("this AmneziaWG outbound has no settings")
	}
	if err := json.Unmarshal([]byte(cfg.Settings), st); err != nil {
		return st, fmt.Errorf("bad AmneziaWG outbound settings: %w", err)
	}
	return st, nil
}

func (d *awgOutDriver) iface(cfg VpnOutboundConfig) string {
	return vpnOutIfaceName(vpnOutAwgIfacePrefix, cfg.Tag)
}

// Validate rejects a config before anything is brought up. The kernel module's own
// parameter checks are left to it: this covers the shapes that would otherwise fail
// as an unexplained EINVAL from netlink.
func (d *awgOutDriver) Validate(cfg VpnOutboundConfig) error {
	st, err := d.settings(cfg)
	if err != nil {
		return err
	}
	return st.validate()
}

func (o *awgOutSettings) validate() error {
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
	if err := vpnOutCheckMTUKeepalive(o.Mtu, o.Keepalive, addrs); err != nil {
		return err
	}

	b := o.obfs()
	// Junk packets are only emitted when Jc > 0, and then their size is drawn from
	// [Jmin, Jmax]. An inverted or empty range is a config the module cannot honour.
	if b.Jc > 0 && (b.Jmax <= 0 || b.Jmin > b.Jmax) {
		return fmt.Errorf("jc is %d but the junk size range %d-%d is empty (set jmin <= jmax, jmax > 0)",
			b.Jc, b.Jmin, b.Jmax)
	}
	// The magic headers replace the four WireGuard message types, so a partial set
	// would leave some packets typed the standard way and some not, and the far end
	// drops whichever half disagrees with it. All four or none.
	set := 0
	for _, h := range []string{b.H1, b.H2, b.H3, b.H4} {
		if h != "" {
			set++
		}
	}
	if set != 0 && set != 4 {
		return errors.New("h1, h2, h3 and h4 must all be set or all be empty (they replace the four packet types together)")
	}
	return nil
}

// Up brings the client tunnel up and returns its interface name. Idempotent: see
// wgOutDriver.Up. The obfuscation parameters ride along with the key/peer push.
func (d *awgOutDriver) Up(cfg VpnOutboundConfig) (string, error) {
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
	endpoint, err := net.ResolveUDPAddr("udp", strings.TrimSpace(st.Endpoint))
	if err != nil {
		return "", fmt.Errorf("endpoint %q: %w", st.Endpoint, err)
	}

	iface := d.iface(cfg)
	// Device only. Egress routing is the framework's (vpnOutBindEgress); see the same
	// note in vpnout_wireguard.go.
	err = vpnOutEnsureLink(iface, st.mtu(), addrs, func(la netlink.LinkAttrs) netlink.Link {
		return &netlink.GenericLink{LinkAttrs: la, LinkType: amneziawgLinkKind}
	})
	if err != nil {
		if isNotSupported(err) {
			return "", fmt.Errorf("amneziawg kernel module unavailable: %s (%w)", awgOutUnavailableReason(), err)
		}
		return "", err
	}

	cl, err := wgctrl.New()
	if err != nil {
		return "", fmt.Errorf("wgctrl: %w", err)
	}
	defer cl.Close()

	if err := d.configure(cl, iface, priv, peerPub, psk, endpoint, st.keepalive(),
		st.obfs(), vpnOutHasV6(addrs)); err != nil {
		return "", fmt.Errorf("configuring %s: %w", iface, err)
	}
	return iface, nil
}

// configure reconciles the device to exactly one peer (the remote server) plus the
// obfuscation set, touching the kernel only when something differs. Mirrors
// wgOutDriver.configure; the obfuscation is folded into the same write because the
// module takes it as device-level config alongside the private key.
func (d *awgOutDriver) configure(cl *wgctrl.Client, iface string, priv, peerPub wgtypes.Key,
	psk *wgtypes.Key, endpoint *net.UDPAddr, keepalive time.Duration, obfs awgObfs, withV6 bool) error {

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
		// An explicit zero key is how a removed preshared key is cleared; nil would
		// mean "leave whatever is there".
		var zero wgtypes.Key
		peer.PresharedKey = &zero
	}

	needKey := derr != nil || dev == nil || dev.PublicKey != priv.PublicKey()
	pushPeer := needKey || cur == nil ||
		allowedIPsKey(cur.AllowedIPs) != allowedIPsKey(allowed) ||
		cur.PersistentKeepaliveInterval != keepalive ||
		cur.PresharedKey != *peer.PresharedKey

	sig := obfs.sig() + "|" + endpoint.String()
	changed := d.appliedChanged(iface, sig)
	if cur == nil || cur.Endpoint == nil || changed {
		peer.Endpoint = endpoint
		pushPeer = true
	}

	var ops []wgtypes.PeerConfig
	if pushPeer {
		ops = append(ops, peer)
	}
	// A client device has exactly one peer; anything else is left over from an edit
	// that changed the server's key.
	if dev != nil {
		for _, p := range dev.Peers {
			if p.PublicKey != peerPub {
				ops = append(ops, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
			}
		}
	}
	needObfs := needKey || changed
	if !needKey && !needObfs && len(ops) == 0 {
		return nil // steady state: do not disturb the live session
	}

	// ListenPort stays unset (a client dials out, so the kernel's ephemeral port is
	// right and cannot collide with an awg INBOUND on this host).
	wcfg := wgtypes.Config{ReplacePeers: false, Peers: ops}
	if needKey {
		wcfg.PrivateKey = &priv
	}
	if needObfs {
		obfs.apply(&wcfg)
	}
	if err := cl.ConfigureDevice(iface, wcfg); err != nil {
		return err
	}
	d.rememberApplied(iface, sig)
	return nil
}

// Down removes the tunnel, tolerating an already-absent link.
func (d *awgOutDriver) Down(cfg VpnOutboundConfig) error {
	iface := d.iface(cfg)
	err := vpnOutDeleteLink(iface, vpnOutAwgIfacePrefix)
	if prev := strings.TrimSpace(cfg.Iface); prev != "" && prev != iface {
		if perr := vpnOutDeleteLink(prev, vpnOutAwgIfacePrefix); err == nil {
			err = perr
		}
	}
	d.forgetApplied(iface)
	return err
}

// Status reports liveness from the last handshake, the only honest signal here (see
// wgOutDriver.Status). A missing interface is reported against module availability,
// because on this protocol "not built for the running kernel" is the likeliest
// reason the tunnel is not there at all.
func (d *awgOutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	st, err := d.settings(cfg)
	if err != nil {
		return false, err.Error()
	}
	iface := d.iface(cfg)
	if _, err := netlink.LinkByName(iface); err != nil {
		if !moduleAvailable(amneziawgModule) {
			return false, "amneziawg kernel module unavailable: " + awgOutUnavailableReason()
		}
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

// awgOutUnavailableReason explains a missing amneziawg module in the operator's
// terms. awgKernelModuleSupported already knows which hosts can never build it (the
// kernel 7.1 ipv6_stub removal, the RHEL-family compat breakage), so a host that
// will never work is told that instead of being sent to a setup run that cannot
// succeed.
//
// The buildable branch names "Core Settings" deliberately, and it is the only reason
// string in the outbound drivers that may: the picker turns that phrase into a link to
// the page (see vpnCoreSettingsHref in modals/xray_outbound_modal.html). A driver
// whose requirement CANNOT be installed there must not name the page, or the operator
// is sent to a screen with nothing on it that helps.
func awgOutUnavailableReason() string {
	if ok, why := awgKernelModuleSupported(); !ok {
		return why
	}
	return "install the AmneziaWG core in Core Settings, which DKMS-builds it for this kernel"
}

func (d *awgOutDriver) appliedChanged(iface, sig string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastApplied[iface] != sig
}

func (d *awgOutDriver) rememberApplied(iface, sig string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lastApplied == nil {
		d.lastApplied = make(map[string]string)
	}
	d.lastApplied[iface] = sig
}

func (d *awgOutDriver) forgetApplied(iface string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.lastApplied, iface)
}
