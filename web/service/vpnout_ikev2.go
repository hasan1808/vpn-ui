package service

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/vishvananda/netlink"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// IKEv2 as an OUTBOUND: the panel is the initiator against somebody else's IKEv2 server.
//
// charon is symmetric, so this costs no new daemon and no new binary: one more file under
// /etc/swanctl/conf.d with `start_action = start` turns the same shared charon that serves
// the IKEv2 inbounds into a client. Everything interesting is in the data plane instead.
//
// THE OBSTACLE: this panel runs charon with `install_routes = no` (charon.go) and pure
// XFRM policies, because the inbound side owns routing through nftables TPROXY. Pure XFRM
// is policy-based IPsec: there is no netdev anywhere. Traffic is selected by policy, not
// by being sent to an interface. That is fine for a server terminating clients, and
// useless here, because the whole outbound framework hangs off SO_BINDTODEVICE
// (streamSettings.sockopt.interface) and a socket cannot be bound to a policy.
//
// THE ANSWER: an XFRM INTERFACE. A netdev of type `xfrm` carries an `if_id`; the swanctl
// connection tags its CHILD_SA with the same value through `if_id_out`/`if_id_in`, and the
// kernel then matches the two. A packet sent out of the interface is looked up against
// policies carrying that if_id and comes back encapsulated in ESP; a decrypted inbound
// packet whose SA carries the if_id is re-injected on the interface. That gives us the
// real device the framework needs, without asking charon to install a single route: the
// route to the peer stays the host's own, and the only route through the tunnel is the
// framework's private one (vpnOutBindEgress).
//
// A packet sent into the interface with no matching policy is DROPPED by the kernel
// (xfrmi_xmit fails the link), which is the right failure: when the SA is down this
// outbound stalls rather than leaking cleartext out of the WAN.
//
// Requires CONFIG_XFRM_INTERFACE (kernel 4.19+) and strongSwan 5.8+; the bundle is 5.9.14.

const (
	// ikev2OutIfIDBase is only a bit mixer input, see ikev2OutIfID.
	ikev2OutIfIDBase = "vpn-ui:ikev2-outbound:"

	// ikev2OutSATimeout bounds how long Up waits for the IKE_SA. Kept tight: tunnels are
	// raised serially at panel boot, so this is startup latency when a gateway is down.
	// Generous against a healthy one even with EAP, which is several round trips and a
	// RADIUS lookup at the far end.
	ikev2OutSATimeout = 20 * time.Second
)

// ikev2OutSettings is the operator-facing shape stored in VpnOutboundConfig.Settings.
// The certificate fields mirror the inbound side's model (ikev2Settings) so the panel can
// reuse the same widget: either paths (TlsUseFile) or inline PEM.
type ikev2OutSettings struct {
	Server string `json:"server"` // the IKEv2 gateway we dial

	// AuthMode selects how WE authenticate to the gateway:
	//   "eap-mschapv2" (default) - username/password, the common remote-access case
	//   "psk"                    - a shared pre-shared key
	//   "cert"                   - our own certificate (the initiator half of eap-tls)
	AuthMode string `json:"authMode"`

	Username string `json:"username"` // eap-mschapv2: the EAP identity
	Password string `json:"password"`
	Psk      string `json:"psk"` // psk mode

	// LocalID is the identity we present (IKEv2 IDi). Optional; charon derives one from
	// our certificate or address when empty.
	LocalID string `json:"localId"`
	// ServerID is the identity we require the gateway to prove (IKEv2 IDr). Defaults to
	// the dialled address, which is what a correctly issued gateway certificate carries
	// as a SAN. "%any" turns the check off, which is a real downgrade and therefore has
	// to be typed.
	ServerID string `json:"serverId"`

	TlsUseFile      bool   `json:"tlsUseFile"`
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
	CaCertFile      string `json:"caCertFile"`
	Certificate     string `json:"certificate"`
	Key             string `json:"key"`
	CaCert          string `json:"caCert"`

	// LocalAddr pins our tunnel address instead of asking the gateway for one. Empty (the
	// normal case) requests a virtual IP through the configuration payload.
	LocalAddr string `json:"localAddr"`
	// RemoteTS is what we ask to reach through the tunnel. Defaults to everything.
	RemoteTS string `json:"remoteTs"`

	Mtu int `json:"mtu"`
}

type ikev2OutDriver struct{}

func init() { RegisterVpnOutDriver(VpnOutIKEv2, &ikev2OutDriver{}) }

// SecretKeys names the settings the panel must never be shown: the EAP password, the
// pre-shared key, and the client's PRIVATE key.
//
// The certificates are deliberately NOT in this list. A certificate and a CA are public
// by construction, they are what the two ends show each other, and hiding them would
// only mean the form could not display the trust anchor an operator is trying to check.
// The three *File fields are paths rather than material and stay visible for the same
// reason: an operator editing a tunnel needs to see which file it reads.
func (d *ikev2OutDriver) SecretKeys() []string { return []string{"password", "psk", "key"} }

// Available reports whether an IKEv2 client can run on this host at all.
//
// The BUNDLE only, with no host-charon fallback, because Up has none either: it
// refuses outright without backend.HasStrongswanBundle(). This used to accept a charon
// found on PATH, which promised something the panel then would not deliver - the
// operator installed their distribution's strongSwan, watched the picker enable IKEv2,
// and got "the IKEv2 client needs the bundled strongSwan" from the save.
//
// Only the daemon is checked. The other hard requirement, a kernel with
// CONFIG_XFRM_INTERFACE, cannot be established without actually creating a device:
// built-in support leaves no /sys/module entry to look for, so the only honest answers
// are "try it" or a false negative that hides a working setup. ensureXfrmLink asks the
// kernel directly and says so in its error.
func (d *ikev2OutDriver) Available() (bool, string) {
	if backend.HasStrongswanBundle() {
		return true, ""
	}
	return false, "IKEv2 dials through the bundled strongSwan, which this build does not carry for " +
		runtime.GOARCH + ". A host strongSwan is not used, and no core installs one, so this needs a vpn-ui build for this architecture"
}

func (d *ikev2OutDriver) parse(cfg VpnOutboundConfig) (*ikev2OutSettings, error) {
	s := &ikev2OutSettings{}
	if len(cfg.Settings) > 0 {
		if err := json.Unmarshal(cfg.Settings, s); err != nil {
			return nil, fmt.Errorf("ikev2 outbound %q: unreadable settings: %w", cfg.Tag, err)
		}
	}
	s.Server = strings.TrimSpace(s.Server)
	s.AuthMode = strings.ToLower(strings.TrimSpace(s.AuthMode))
	if s.AuthMode == "" {
		s.AuthMode = "eap-mschapv2"
	}
	s.Username = strings.TrimSpace(s.Username)
	s.Psk = strings.TrimSpace(s.Psk)
	s.LocalID = strings.TrimSpace(s.LocalID)
	s.ServerID = strings.TrimSpace(s.ServerID)
	s.LocalAddr = strings.TrimSpace(s.LocalAddr)
	s.RemoteTS = strings.TrimSpace(s.RemoteTS)
	return s, nil
}

// Validate refuses a config that cannot authenticate, before anything is brought up.
func (d *ikev2OutDriver) Validate(cfg VpnOutboundConfig) error {
	s, err := d.parse(cfg)
	if err != nil {
		return err
	}
	if s.Server == "" {
		return errors.New("the IKEv2 gateway address is required")
	}
	switch s.AuthMode {
	case "eap-mschapv2":
		if s.Username == "" || s.Password == "" {
			return errors.New("EAP-MSCHAPv2 needs a username and a password")
		}
		if strings.ContainsAny(s.Username, "\r\n") || strings.ContainsAny(s.Password, "\r\n") {
			return errors.New("username and password cannot contain line breaks")
		}
	case "psk":
		if s.Psk == "" {
			return errors.New("PSK authentication needs a pre-shared key")
		}
		if strings.ContainsAny(s.Psk, "\r\n") {
			return errors.New("the pre-shared key cannot contain line breaks")
		}
	case "cert":
		if s.TlsUseFile {
			for _, p := range []string{s.CertificateFile, s.KeyFile} {
				if strings.TrimSpace(p) == "" {
					return errors.New("certificate authentication needs a client certificate and its private key")
				}
				if _, err := os.Stat(strings.TrimSpace(p)); err != nil {
					return fmt.Errorf("cannot read %s: %w", strings.TrimSpace(p), err)
				}
			}
			break
		}
		if strings.TrimSpace(s.Certificate) == "" || strings.TrimSpace(s.Key) == "" {
			return errors.New("certificate authentication needs a client certificate and its private key")
		}
	default:
		return fmt.Errorf("unknown authentication mode %q", s.AuthMode)
	}
	if s.LocalAddr != "" {
		if ip := net.ParseIP(s.LocalAddr); ip == nil || ip.To4() == nil {
			return fmt.Errorf("the local tunnel address %q is not an IPv4 address", s.LocalAddr)
		}
	}
	if s.RemoteTS != "" {
		if _, _, err := net.ParseCIDR(s.RemoteTS); err != nil {
			return fmt.Errorf("the remote traffic selector %q is not a CIDR", s.RemoteTS)
		}
	}
	if s.Mtu != 0 && (s.Mtu < 576 || s.Mtu > 1500) {
		return fmt.Errorf("mtu %d is outside 576..1500", s.Mtu)
	}
	return nil
}

// Up creates the XFRM interface, loads the connection into the shared charon, waits for
// the SA and returns the interface for Xray to bind to.
func (d *ikev2OutDriver) Up(cfg VpnOutboundConfig) (string, error) {
	s, err := d.parse(cfg)
	if err != nil {
		return "", err
	}
	if err := d.Validate(cfg); err != nil {
		return "", err
	}
	if !backend.HasStrongswanBundle() {
		return "", errors.New("the IKEv2 client needs the bundled strongSwan, which is not available for this architecture")
	}

	name := ikev2OutSafeName(cfg.Tag)
	iface := ikev2OutIfName(cfg.Tag)
	ifID := ikev2OutIfID(cfg.Tag)
	conn := ikev2OutConnName(name)

	// Idempotence, keyed on a fingerprint of the settings rather than on the tunnel
	// merely being up. Up runs on save, at boot and on reconcile; returning early on a
	// live-but-stale tunnel would report a changed password as saved while charon kept
	// using the old one.
	if ikev2OutStoredFingerprint(name) == ikev2OutFingerprint(s) {
		if up, vip := ikev2OutSAState(conn); up {
			// Re-asserted, not assumed: the address is the one thing here that another
			// process (charon, on reauthentication) moves out from under us.
			if err := d.ensureXfrmLink(iface, ifID, s); err == nil {
				if err := d.syncTunnelAddr(iface, s, vip); err == nil {
					return iface, nil
				}
			}
		}
	}

	if err := d.ensureXfrmLink(iface, ifID, s); err != nil {
		return "", err
	}

	// /etc/strongswan.conf and swanctl.conf belong to whichever inbound protocol needs
	// charon; write them only when nobody has, so an outbound-only box still gets a
	// daemon it can boot on while a server box keeps the files its own services
	// generated. swanctl.conf matters as much as the other: it is the `include
	// conf.d/*.conf` line, without which our connection file is never read at all.
	if !ikev2OutFileExists("/etc/strongswan.conf") || !ikev2OutFileExists(swanctlDir+"/swanctl.conf") {
		if err := writeCharonConf(); err != nil {
			return "", fmt.Errorf("write the shared charon config: %w", err)
		}
	}
	_ = os.MkdirAll(swanctlConfDir, 0755)
	if err := d.writeCreds(name, s); err != nil {
		return "", err
	}
	if err := d.writeConnConf(name, iface, ifID, s); err != nil {
		return "", err
	}
	// ensureCharonRunning, never syncCharon: syncCharon decides charon's fate from the
	// INBOUND table alone and would stop the daemon on a box whose only IPsec user is
	// this outbound. Starting it here is safe when it is already up (the call is a no-op)
	// and reloadCharon merges every conf.d file without dropping a single live SA.
	if err := ensureCharonRunning(); err != nil {
		return "", err
	}
	if err := reloadCharon(); err != nil {
		return "", err
	}

	up, vip := false, ""
	deadline := time.Now().Add(ikev2OutSATimeout)
	for {
		if up, vip = ikev2OutSAState(conn); up {
			break
		}
		if time.Now().After(deadline) {
			d.teardown(name, iface)
			return "", fmt.Errorf("the IKEv2 SA to %s did not establish within %s; check the credentials, the gateway identity, and that UDP 500/4500 reach it",
				s.Server, ikev2OutSATimeout)
		}
		time.Sleep(time.Second)
	}

	if err := d.syncTunnelAddr(iface, s, vip); err != nil {
		d.teardown(name, iface)
		return "", err
	}
	// The route and the `oif` rule that let a pinned socket send belong to the framework
	// (vpnOutBindEgress, on the way out of bringUp). What is left here is the XFRM
	// interface's own sysctls, which nothing outside this driver knows it needs.
	ikev2OutTuneIface(iface)
	return iface, nil
}

// Down terminates the SA, unloads the connection and removes the interface.
func (d *ikev2OutDriver) Down(cfg VpnOutboundConfig) error {
	name := ikev2OutSafeName(cfg.Tag)
	iface := strings.TrimSpace(cfg.Iface)
	if iface == "" {
		iface = ikev2OutIfName(cfg.Tag)
	}
	d.teardown(name, iface)
	return nil
}

// teardown is the common cleanup path for Down and for a failed Up.
func (d *ikev2OutDriver) teardown(name, iface string) {
	conn := ikev2OutConnName(name)
	if procMgr.IsRunning(ikev2ProcName) {
		// --timeout, because a bare --terminate WAITS for the delete exchange to complete
		// and an unreachable gateway makes charon retransmit for the best part of a
		// minute. Down runs on panel shutdown, once per tunnel, in series.
		_ = exec.Command(swanctlBin(), "--terminate", "--ike", conn, "--timeout", "5").Run()
	}
	hadConf := false
	if _, err := os.Stat(ikev2OutConnFile(name)); err == nil {
		hadConf = true
	}
	_ = os.Remove(ikev2OutConnFile(name))
	d.removeCreds(name)
	if hadConf && procMgr.IsRunning(ikev2ProcName) {
		// --load-all unloads connections that are no longer in any conf.d file, which is
		// what actually removes ours. The inbound protocols' connections are reloaded from
		// their own files in the same pass and keep their SAs.
		_ = reloadCharon()
	}

	// The egress rule and route are the framework's (vpnOutUnbindEgress runs on every
	// teardown path it owns), so only the interface itself is ours to remove.
	if link, err := netlink.LinkByName(iface); err == nil {
		if _, ok := link.(*netlink.Xfrmi); ok {
			_ = netlink.LinkDel(link)
		}
	}
}

// Status reports the SA state and the tunnel address.
func (d *ikev2OutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	name := ikev2OutSafeName(cfg.Tag)
	iface := ikev2OutIfName(cfg.Tag)
	if _, err := netlink.LinkByName(iface); err != nil {
		return false, "no tunnel interface"
	}
	if !procMgr.IsRunning(ikev2ProcName) {
		// Worth saying plainly: the most likely cause is that an inbound change ran
		// syncCharon, which stops the shared daemon when no INBOUND still needs it.
		return false, "the shared IPsec daemon is not running"
	}
	up, vip := ikev2OutSAState(ikev2OutConnName(name))
	if !up {
		return false, "IKE SA down"
	}
	if vip == "" {
		vip = ikev2OutIfaceAddr(iface)
	}
	if vip == "" {
		return true, iface
	}
	return true, iface + " " + vip
}

// ---------------------------------------------------------------------------
// naming
// ---------------------------------------------------------------------------

// ikev2OutSafeName reduces a tag to something usable as a filename, a connection name and
// part of a netdev name.
func ikev2OutSafeName(tag string) string {
	var b strings.Builder
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

func ikev2OutHash(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// ikev2OutIfName is the XFRM interface's name. 15 characters is the kernel's limit, so a
// long tag is truncated to three characters plus its hash rather than colliding with a
// neighbouring tag's device.
func ikev2OutIfName(tag string) string {
	safe := ikev2OutSafeName(tag)
	if len(safe) <= 11 {
		return "ike-" + safe
	}
	return fmt.Sprintf("ike-%.3s%08x", safe, ikev2OutHash(tag))
}

// ikev2OutIfID is the XFRM if_id tying this interface to its CHILD_SA.
//
// Derived from the tag so it survives a panel restart with no state to persist, and so
// two tunnels cannot be handed the same value by an allocator that forgot what it gave
// out last boot. Zero is reserved by the kernel ("if_id must be non zero"), so it is
// mapped away rather than allowed to happen once in four billion tags.
func ikev2OutIfID(tag string) uint32 {
	id := ikev2OutHash(ikev2OutIfIDBase + tag)
	if id == 0 {
		return 1
	}
	return id
}

func ikev2OutConnName(name string) string { return "vpnout-ike-" + name }

func ikev2OutFileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// ikev2OutConnFile is this tunnel's file in the shared conf.d. The `vpnout-` prefix keeps
// it out of every namespace the server side sweeps: ikev2.go deletes conf.d/ikev2-*.conf
// wholesale on each regenerate, gre.go globs gre-*.conf, l2tp.go owns l2tp.conf.
func ikev2OutConnFile(name string) string {
	return swanctlConfDir + "/" + ikev2OutConnName(name) + ".conf"
}

// ikev2OutCredBase is the filename stem for this tunnel's credentials in the swanctl
// credential directories, which are shared with the inbound side.
func ikev2OutCredBase(name string) string { return ikev2OutConnName(name) }

// ---------------------------------------------------------------------------
// the XFRM interface
// ---------------------------------------------------------------------------

// ensureXfrmLink creates (or adopts) the XFRM interface this tunnel egresses through.
//
// Idempotent: an existing interface of the right type and if_id is left in place, because
// deleting and recreating it would drop every socket Xray currently has bound to it. An
// existing interface with the WRONG if_id is replaced, since it cannot carry this
// tunnel's SA. Anything else with that name is refused rather than deleted: it belongs to
// someone else.
func (d *ikev2OutDriver) ensureXfrmLink(iface string, ifID uint32, s *ikev2OutSettings) error {
	mtu := s.Mtu
	if mtu == 0 {
		// ESP over UDP costs roughly 100 bytes on a 1500 byte path. A tunnel MTU that
		// ignores that produces packets the peer must fragment or drop, which shows up as
		// "small requests work, downloads hang" rather than as an error.
		mtu = 1400
	}

	if existing, err := netlink.LinkByName(iface); err == nil {
		xi, ok := existing.(*netlink.Xfrmi)
		if !ok {
			return fmt.Errorf("the device %q already exists and is not an XFRM interface; rename the outbound", iface)
		}
		if xi.Ifid == ifID {
			if existing.Attrs().MTU != mtu {
				_ = netlink.LinkSetMTU(existing, mtu)
			}
			ikev2OutTuneIface(iface)
			return netlink.LinkSetUp(existing)
		}
		if err := netlink.LinkDel(existing); err != nil {
			return fmt.Errorf("replace the stale XFRM interface %q: %w", iface, err)
		}
	}

	// Built into most target kernels, a module on some. Best effort, exactly like the
	// esp4/xfrm_user preload the inbound side does in SetupRouting.
	_ = exec.Command("modprobe", "xfrm_interface").Run()

	la := netlink.NewLinkAttrs()
	la.Name = iface
	la.MTU = mtu
	// The underlying device. `ip link add ... type xfrm dev <wan> if_id <n>` is the
	// documented form and older kernels want it; on current ones it is advisory (the SA
	// decides which path the ESP packets actually take). Zero when there is no default
	// route, which is a box that has bigger problems than this tunnel.
	la.ParentIndex = ikev2OutWanIndex()

	if err := netlink.LinkAdd(&netlink.Xfrmi{LinkAttrs: la, Ifid: ifID}); err != nil {
		return fmt.Errorf("create the XFRM interface %q (if_id %d): %w; a kernel without CONFIG_XFRM_INTERFACE cannot run an IKEv2 outbound",
			iface, ifID, err)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	ikev2OutTuneIface(iface)
	return netlink.LinkSetUp(link)
}

// ikev2OutTuneIface applies the one sysctl this tunnel needs and the framework cannot.
//
// disable_policy, on the XFRM interface. Decrypted packets are re-injected on this device
// and run through the input path again, where the IPsec policy check can drop them (the
// policy that matched carries our if_id, the check does not). strongSwan's own
// route-based recipe sets this for the same reason. It does NOT weaken the outbound
// direction: that is gated by DST_NOXFRM (the disable_xfrm knob), which we leave alone, so
// traffic sent into this device is still required to match a policy or be dropped.
//
// rp_filter is deliberately NOT here. It needs both conf.all and conf.<dev> (the kernel
// enforces the maximum of the two, so relaxing only the device changes nothing on a host
// that ships all=1), and vpnOutBindEgress does both on the way out of bringUp for every
// protocol. This driver used to carry its own copy back when the framework relaxed only
// the device.
func ikev2OutTuneIface(iface string) {
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf."+iface+".disable_policy=1").Run()
}

// ikev2OutWanIndex returns the interface index of the default route, or 0.
func ikev2OutWanIndex() int {
	routes, err := netlink.RouteGet(net.IPv4(1, 1, 1, 1))
	if err != nil || len(routes) == 0 {
		return 0
	}
	return routes[0].LinkIndex
}

// syncTunnelAddr puts our tunnel address on the XFRM interface.
//
// This is not optional and it is not charon's job here. charon does install the virtual
// IP it was assigned, but on the interface holding our outbound address (the WAN),
// because the setting that would redirect it, charon.install_virtual_ip_on, lives in the
// shared /etc/strongswan.conf that the inbound protocols generate. Left like that, a
// socket bound to the XFRM interface finds no address on it, the kernel sources the
// packet from some other interface's address, and the gateway drops it for failing the
// traffic selector: a tunnel that establishes perfectly and carries nothing.
//
// The copy on the WAN is removed for hygiene: a VPN address sitting on the public
// interface is a candidate source address for traffic that has nothing to do with this
// tunnel.
func (d *ikev2OutDriver) syncTunnelAddr(iface string, s *ikev2OutSettings, vip string) error {
	addr := s.LocalAddr
	if addr == "" {
		addr = vip
	}
	if addr == "" {
		return fmt.Errorf("the gateway did not assign a tunnel address and none is configured")
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("the tunnel address %q is not an IPv4 address", addr)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	want := &netlink.Addr{IPNet: &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrReplace(link, want); err != nil {
		return fmt.Errorf("assign %s to %s: %w", addr, iface, err)
	}

	// Strip the same address wherever else charon put it. Best effort by design: charon
	// re-adds it on reauthentication, and the next reconcile pass cleans up again.
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	for _, l := range links {
		if l.Attrs().Name == iface || l.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}
		// Never touch another XFRM interface: two gateways can hand out the same private
		// address, and stripping it would break the OTHER tunnel that legitimately holds
		// it. Only the copy charon left on an ordinary interface is ours to remove.
		if _, ok := l.(*netlink.Xfrmi); ok {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			continue
		}
		for i := range addrs {
			if addrs[i].IP.Equal(ip) {
				if err := netlink.AddrDel(l, &addrs[i]); err != nil {
					logger.Debug("ikev2 outbound: leaving", addr, "on", l.Attrs().Name, ":", err)
				}
			}
		}
	}
	return nil
}

// ikev2OutIfaceAddr returns the device's first IPv4 address, or "".
func ikev2OutIfaceAddr(iface string) string {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return ""
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if a.IP != nil {
			return a.IP.String()
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// swanctl connection and credentials
// ---------------------------------------------------------------------------

// credentials returns the client certificate, its key and the CA to verify the gateway,
// from either the operator's paths or the inline PEM fields.
func (d *ikev2OutDriver) credentials(s *ikev2OutSettings) (cert, key, ca []byte) {
	read := func(path string) []byte {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			logger.Warning("ikev2 outbound: cannot read", path, ":", err)
			return nil
		}
		return data
	}
	if s.TlsUseFile {
		return read(s.CertificateFile), read(s.KeyFile), read(s.CaCertFile)
	}
	return []byte(strings.TrimSpace(s.Certificate)),
		[]byte(strings.TrimSpace(s.Key)),
		[]byte(strings.TrimSpace(s.CaCert))
}

// writeCreds publishes this tunnel's credentials into the swanctl credential directories.
//
// They have to be COPIED there, not referenced where they sit: swanctl --load-creds only
// reads its own directories, so a bare path to the operator's file is never loaded. The
// inbound side learned the same thing the hard way (see writeCertFiles in ikev2.go).
func (d *ikev2OutDriver) writeCreds(name string, s *ikev2OutSettings) error {
	_ = os.MkdirAll(swanctlX509, 0755)
	_ = os.MkdirAll(swanctlX509CA, 0755)
	_ = os.MkdirAll(swanctlPrivate, 0700)
	base := ikev2OutCredBase(name)
	cert, key, ca := d.credentials(s)

	if s.AuthMode == "cert" && len(cert) > 0 && len(key) > 0 {
		if err := os.WriteFile(swanctlX509+"/"+base+"-client.pem", cert, 0644); err != nil {
			return err
		}
		if err := os.WriteFile(swanctlPrivate+"/"+base+"-client.key", key, 0600); err != nil {
			return err
		}
	} else {
		_ = os.Remove(swanctlX509 + "/" + base + "-client.pem")
		_ = os.Remove(swanctlPrivate + "/" + base + "-client.key")
	}

	caPath := swanctlX509CA + "/" + base + "-ca.pem"
	if len(ca) > 0 {
		return os.WriteFile(caPath, ca, 0644)
	}
	_ = os.Remove(caPath)
	if s.AuthMode != "psk" {
		// Not fatal: the anchor may already be in x509ca from another tunnel or from the
		// inbound side. But it is the single most common reason a client that is otherwise
		// configured correctly fails with "no trusted RSA public key found", and charon
		// does not consult the host's CA bundle, so say it out loud.
		logger.Warning("ikev2 outbound:", name,
			"has no CA certificate; charon can only verify the gateway against the anchors in", swanctlX509CA)
	}
	return nil
}

func (d *ikev2OutDriver) removeCreds(name string) {
	base := ikev2OutCredBase(name)
	_ = os.Remove(swanctlX509 + "/" + base + "-client.pem")
	_ = os.Remove(swanctlPrivate + "/" + base + "-client.key")
	_ = os.Remove(swanctlX509CA + "/" + base + "-ca.pem")
}

// writeConnConf writes the swanctl connection that turns the shared charon into an
// initiator for this tunnel.
func (d *ikev2OutDriver) writeConnConf(name, iface string, ifID uint32, s *ikev2OutSettings) error {
	conn := ikev2OutConnName(name)
	base := ikev2OutCredBase(name)
	remoteID := s.ServerID
	if remoteID == "" {
		remoteID = s.Server
	}
	remoteTS := s.RemoteTS
	if remoteTS == "" {
		remoteTS = "0.0.0.0/0"
	}

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui (IKEv2 client outbound on the shared charon) - do not edit\n")
	// Named here so an operator reading conf.d can tie the connection to the netdev its
	// traffic actually leaves through; the if_id below is the only thing that binds them.
	b.WriteString(fmt.Sprintf("# egress interface: %s (if_id %d)\n", iface, ifID))
	b.WriteString(ikev2OutFingerprintMark + ikev2OutFingerprint(s) + "\n")
	b.WriteString("connections {\n")
	b.WriteString(fmt.Sprintf("    %s {\n", conn))
	b.WriteString("        version = 2\n")
	b.WriteString(fmt.Sprintf("        remote_addrs = %s\n", s.Server))
	b.WriteString("        rekey_time = 4h\n")
	b.WriteString("        dpd_delay = 30s\n")
	b.WriteString("        fragmentation = yes\n")
	// mobike lets the SA survive our own address changing, which is what a client wants.
	b.WriteString("        mobike = yes\n")
	// We propose, the gateway picks. Strong suites first, `default` to cover the rest.
	b.WriteString("        proposals = aes256-sha256-modp2048,aes256gcm16-prfsha256-ecp256,aes128-sha256-modp2048,aes256-sha1-modp1024,default\n")
	if s.LocalAddr == "" {
		// Ask for an address through the configuration payload. `0.0.0.0` is swanctl's
		// "any IPv4 address you like", not a literal.
		b.WriteString("        vips = 0.0.0.0\n")
	}

	switch s.AuthMode {
	case "psk":
		b.WriteString("        local {\n            auth = psk\n")
		if s.LocalID != "" {
			b.WriteString(fmt.Sprintf("            id = %s\n", s.LocalID))
		}
		b.WriteString("        }\n")
		b.WriteString(fmt.Sprintf("        remote {\n            auth = psk\n            id = %s\n        }\n", remoteID))
	case "cert":
		b.WriteString("        local {\n            auth = pubkey\n")
		b.WriteString(fmt.Sprintf("            certs = %s-client.pem\n", base))
		if s.LocalID != "" {
			b.WriteString(fmt.Sprintf("            id = %s\n", s.LocalID))
		}
		b.WriteString("        }\n")
		b.WriteString(fmt.Sprintf("        remote {\n            auth = pubkey\n            id = %s\n        }\n", remoteID))
	default: // eap-mschapv2
		// The client half of the inbound side's eap-radius connection: there we terminate
		// EAP and forward it to the panel's RADIUS server, here we are the supplicant. The
		// in-binary RADIUS server is not involved in any way; these credentials belong to
		// somebody else's account on somebody else's gateway.
		b.WriteString("        local {\n            auth = eap-mschapv2\n")
		b.WriteString(fmt.Sprintf("            eap_id = %s\n", s.Username))
		if s.LocalID != "" {
			b.WriteString(fmt.Sprintf("            id = %s\n", s.LocalID))
		}
		b.WriteString("        }\n")
		// The gateway authenticates with its certificate. Pinning its identity is what
		// stops us from handing the account's EAP credentials to whoever answers on that
		// address, so it defaults to the address dialled rather than %any.
		b.WriteString(fmt.Sprintf("        remote {\n            auth = pubkey\n            id = %s\n        }\n", remoteID))
	}

	b.WriteString("        children {\n")
	b.WriteString("            net {\n")
	if s.LocalAddr != "" {
		b.WriteString(fmt.Sprintf("                local_ts = %s/32\n", s.LocalAddr))
	} else {
		// `dynamic` is substituted with the virtual IP the gateway assigns.
		b.WriteString("                local_ts = dynamic\n")
	}
	b.WriteString(fmt.Sprintf("                remote_ts = %s\n", remoteTS))
	// The crux: tagging the CHILD_SA's policies and SAs with the same if_id the XFRM
	// interface carries is what binds them together. Without these two lines the SA is
	// installed with if_id 0, nothing sent into the interface matches a policy, and the
	// kernel drops every packet at xfrmi_xmit while swanctl cheerfully reports the tunnel
	// as ESTABLISHED and INSTALLED.
	b.WriteString(fmt.Sprintf("                if_id_out = %d\n", ifID))
	b.WriteString(fmt.Sprintf("                if_id_in = %d\n", ifID))
	b.WriteString("                esp_proposals = aes256gcm16,aes256-sha256,aes128-sha256,aes256-sha1,default\n")
	b.WriteString("                rekey_time = 1h\n")
	// A client dials, and keeps dialling: start on load, re-establish on DPD timeout and
	// when the gateway closes the SA. Otherwise a peer's nightly restart leaves the
	// outbound down until somebody notices.
	b.WriteString("                start_action = start\n")
	b.WriteString("                dpd_action = restart\n")
	b.WriteString("                close_action = restart\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	switch s.AuthMode {
	case "psk":
		esc := strings.ReplaceAll(s.Psk, `\`, `\\`)
		esc = strings.ReplaceAll(esc, `"`, `\"`)
		b.WriteString("secrets {\n")
		b.WriteString(fmt.Sprintf("    ike-%s {\n", conn))
		// Two owners, for the reason greipsec.go documents: a secret that lists owners must
		// match BOTH ends, so naming only the peer makes it unusable and charon silently
		// falls back to another connection's owner-less key (the L2TP inbound writes one)
		// and signs with the wrong secret.
		b.WriteString(fmt.Sprintf("        id_remote = %s\n", remoteID))
		b.WriteString("        id_any = %any\n")
		b.WriteString(fmt.Sprintf("        secret = \"%s\"\n", esc))
		b.WriteString("    }\n")
		b.WriteString("}\n")
	case "eap-mschapv2":
		esc := strings.ReplaceAll(s.Password, `\`, `\\`)
		esc = strings.ReplaceAll(esc, `"`, `\"`)
		b.WriteString("secrets {\n")
		b.WriteString(fmt.Sprintf("    eap-%s {\n", conn))
		b.WriteString(fmt.Sprintf("        id = %s\n", s.Username))
		b.WriteString(fmt.Sprintf("        secret = \"%s\"\n", esc))
		b.WriteString("    }\n")
		b.WriteString("}\n")
	}

	// 0600: the file holds the account's password or the pre-shared key.
	return os.WriteFile(ikev2OutConnFile(name), []byte(b.String()), 0600)
}

// ikev2OutFingerprintMark introduces the settings fingerprint comment in the generated
// connection file.
const ikev2OutFingerprintMark = "# vpn-ui-settings = "

// ikev2OutFingerprint hashes the operator's settings, so a later Up can tell "already
// running" from "already running with what the operator just typed".
func ikev2OutFingerprint(s *ikev2OutSettings) string {
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%08x", ikev2OutHash(string(b)))
}

func ikev2OutStoredFingerprint(name string) string {
	data, err := os.ReadFile(ikev2OutConnFile(name))
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(ln, ikev2OutFingerprintMark) {
			return strings.TrimSpace(strings.TrimPrefix(ln, ikev2OutFingerprintMark))
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// SA state
// ---------------------------------------------------------------------------

// ikev2OutLocalVipRe pulls our assigned tunnel address out of a `local-vips: [10.1.2.3]`
// line, which is the VICI attribute's own name.
var ikev2OutLocalVipRe = regexp.MustCompile(`local-vips:\s*\[([0-9.]+)`)

// ikev2OutLocalLineVipRe pulls the same address out of the IKE_SA's `local` line, which
// is where `swanctl --list-sas` actually puts it:
//
//	local  '91.107.250.175' @ 91.107.250.175[4500] [10.6.0.2]
//
// The bracket the address is in is the LAST one; the first holds the UDP port. swanctl
// prints no `local-vips:` line at all (list_sas.c appends the virtual IPs to the local
// endpoint instead), so matching only that name found nothing on a perfectly established
// SA: measured against the bundled strongSwan 5.9.14, every IKEv2 outbound established
// its SA, got 10.6.0.2 assigned, then failed the save with "the gateway did not assign a
// tunnel address and none is configured" and tore the tunnel back down. Both spellings
// are accepted rather than swapped, so a build against a strongSwan that does emit the
// attribute keeps working.
var ikev2OutLocalLineVipRe = regexp.MustCompile(`(?m)^\s*local\s.*\[\d+\]\s+\[([0-9.]+)`)

// ikev2OutParseVip returns the virtual IP in a `swanctl --list-sas` listing, in either
// spelling, or "" when the gateway assigned none.
func ikev2OutParseVip(s string) string {
	if m := ikev2OutLocalVipRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	if m := ikev2OutLocalLineVipRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// ikev2OutSAState reports whether the connection has a live IKE_SA with an installed
// child, plus the virtual IP the gateway assigned.
//
// Both halves of the state matter: an ESTABLISHED IKE_SA whose CHILD_SA was never
// installed carries nothing, and that is exactly what a traffic-selector the gateway
// refuses to narrow to leaves behind.
//
// --noblock, always: `swanctl --list-sas` otherwise WAITS on any IKE_SA that is checked
// out, which on this shared charon includes an inbound client sitting mid-authentication
// against the panel's own RADIUS server (ikev2.go documents the deadlock from the other
// side). This runs inside the panel's save handler, so a blocking listing would stall an
// HTTP request behind an unrelated client's login.
func ikev2OutSAState(conn string) (bool, string) {
	out, err := exec.Command(swanctlBin(), "--list-sas", "--noblock", "--ike", conn).CombinedOutput()
	if err != nil {
		return false, ""
	}
	s := string(out)
	return strings.Contains(s, "ESTABLISHED") && strings.Contains(s, "INSTALLED"),
		ikev2OutParseVip(s)
}
