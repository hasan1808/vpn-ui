package service

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/goccy/go-json"
	"github.com/vishvananda/netlink"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// L2TP as an OUTBOUND: the panel is the LAC and somebody else's LNS is the far end.
//
// The server side of this protocol (l2tp.go) writes ONE `[lns default]` section into
// /etc/xl2tpd/xl2tpd.conf and runs a single xl2tpd for every L2TP inbound. There has
// never been a `[lac ...]` section anywhere in this panel, so this file adds the other
// half of xl2tpd: a SECOND, fully separate instance that dials out.
//
// "Fully separate" is the whole design constraint. The multi-inbound fix that made the
// server side share one config file means that file is rewritten from DB state whenever
// an inbound changes, so a client section living in it would be erased by the next
// inbound save. This instance therefore gets its own config path, its own control FIFO,
// its own pid file, its own procmgr key and its own UDP port, and touches nothing the
// server side owns.
//
// The pieces:
//
//	xl2tpd (bundled)  -> L2TP control + data channel to the LNS, spawns pppd per call
//	pppd   (bundled)  -> PPP inside it: authenticates us, negotiates our tunnel address
//	charon (shared)   -> optional ESP transport SA protecting UDP <ourport> <-> 1701
//
// Xray egresses through the resulting ppp device via SO_BINDTODEVICE
// (streamSettings.sockopt.interface), which is why Up must return a device name that is
// both correct and stable. See l2tpOutIfName / l2tpOutResolveIface.

const (
	// l2tpOutConfDir holds one xl2tpd config per client tunnel. Deliberately NOT
	// /etc/xl2tpd/: that directory belongs to the server instance, whose config is
	// regenerated wholesale from the inbound table.
	l2tpOutConfDir = "/etc/vpn-ui-l2tp-out"

	// l2tpOutRunDir is where xl2tpd's control FIFO and pid file live. Shared directory,
	// per-tunnel filenames, always passed explicitly with -C/-p so we never inherit the
	// compiled-in defaults (/var/run/xl2tpd/l2tp-control and /var/run/xl2tpd.pid) that
	// the server instance is using.
	l2tpOutRunDir = "/var/run/xl2tpd"

	// The local UDP port range for client instances. 1701 is excluded on purpose: the
	// server instance binds it, and a client that stole it would break every inbound
	// L2TP client on the box. A non-1701 source port is what any LNS already sees from
	// a client behind NAT, so this costs nothing in interoperability.
	l2tpOutPortBase = 17020
	l2tpOutPortSpan = 80

	// How long Up waits for each stage before giving up. Kept tight because
	// InitVpnOutbound raises tunnels serially at panel boot, so the sum of these is how
	// long an unreachable peer delays the whole panel coming up. Both are several times
	// what the exchange takes on a healthy link (IKEv1 well under a second, PPP one to
	// three), so they only bite when something is actually wrong.
	l2tpOutIpsecTimeout = 15 * time.Second
	l2tpOutDialTimeout  = 25 * time.Second
)

// l2tpOutSettings is the operator-facing shape stored in VpnOutboundConfig.Settings.
type l2tpOutSettings struct {
	Server   string `json:"server"`   // LNS hostname or IP
	Username string `json:"username"` // PPP username
	Password string `json:"password"` // PPP password

	// AuthProto pins the PPP authentication protocol we are willing to use:
	// "" / "auto" (anything but EAP), "mschapv2", "chap" or "pap".
	AuthProto string `json:"authProto"`

	// IpsecPsk turns this into L2TP/IPsec. Empty means plain L2TP.
	IpsecPsk string `json:"ipsecPsk"`

	Mtu int `json:"mtu"`
}

type l2tpOutDriver struct{}

func init() { RegisterVpnOutDriver(VpnOutL2TP, &l2tpOutDriver{}) }

// SecretKeys names the settings the panel must never be shown.
//
// Both are credentials for somebody else's server, and both end up in a file this
// driver writes at 0600. The optional framework interface strips them from List(), and
// because Save treats an absent key as "keep the stored value", an operator can change
// the MTU without re-typing either.
//
// The certificate-shaped fields on the IKEv2 side have an equivalent here only in the
// PSK: everything else in this shape (server, username, auth protocol, MTU) has to stay
// visible or the form cannot render what is configured.
func (d *l2tpOutDriver) SecretKeys() []string { return []string{"password", "ipsecPsk"} }

// Available reports whether an L2TP client can run on this host at all.
//
// The optional framework interface, and worth implementing here because both halves of
// this driver are bundled binaries: without it a build for an architecture the daemons
// were never compiled for still offers L2TP in the picker, accepts the save, and only
// then fails to raise, which reads as a broken panel rather than a missing dependency.
// Both halves fall back to a host binary (daemonBin runs a bare "xl2tpd" off PATH, and
// xl2tpd execs whatever pppd is at the hard-coded path), so both reasons name the
// distribution package instead of declaring a dead end. Installing the L2TP CORE is
// deliberately not suggested: it extracts from the same bundle this build does not
// carry, so it would answer nothing, and l2tpOutEnsureBinaries already extracts on
// raise wherever the bundle does exist.
func (d *l2tpOutDriver) Available() (bool, string) {
	if backend.DaemonPath("xl2tpd") == "" && !backend.Available() {
		if _, err := exec.LookPath("xl2tpd"); err != nil {
			return false, "there is no xl2tpd here to dial an LNS with: this build carries no daemon bundle for " +
				runtime.GOARCH + ", so install your distribution's xl2tpd package, which this driver will use"
		}
	}
	// xl2tpd only carries L2TP. PPP, and therefore the authentication and the tunnel
	// address, is pppd's, and xl2tpd execs it by a hard-coded path.
	if !backend.HasPppdBundle() {
		if _, err := os.Stat(backend.PppdSystem); err != nil {
			if _, err := exec.LookPath("pppd"); err != nil {
				return false, "there is no pppd here, so an L2TP tunnel could be set up but never authenticated: " +
					"this build carries no pppd bundle for " + runtime.GOARCH + ", so install your distribution's " +
					"ppp package, which this driver will use"
			}
		}
	}
	return true, ""
}

func (d *l2tpOutDriver) parse(cfg VpnOutboundConfig) (*l2tpOutSettings, error) {
	s := &l2tpOutSettings{}
	if len(cfg.Settings) > 0 {
		if err := json.Unmarshal(cfg.Settings, s); err != nil {
			return nil, fmt.Errorf("l2tp outbound %q: unreadable settings: %w", cfg.Tag, err)
		}
	}
	s.Server = strings.TrimSpace(s.Server)
	s.Username = strings.TrimSpace(s.Username)
	s.IpsecPsk = strings.TrimSpace(s.IpsecPsk)
	s.AuthProto = strings.ToLower(strings.TrimSpace(s.AuthProto))
	return s, nil
}

// Validate refuses a tunnel that cannot possibly come up, while the modal is still open.
func (d *l2tpOutDriver) Validate(cfg VpnOutboundConfig) error {
	s, err := d.parse(cfg)
	if err != nil {
		return err
	}
	if s.Server == "" {
		return errors.New("the LNS address is required")
	}
	if s.Username == "" {
		return errors.New("a PPP username is required")
	}
	if s.Password == "" {
		// PPP with an empty password is not a configuration anybody wants: it is what a
		// half-filled form produces, and it fails at authentication with a message the
		// operator has to go digging in the daemon log to see.
		return errors.New("a PPP password is required")
	}
	// The credentials end up in a pppd options file, whose parser is line oriented.
	if strings.ContainsAny(s.Username+s.Password, "\r\n") {
		return errors.New("username and password cannot contain line breaks")
	}
	if strings.ContainsAny(s.IpsecPsk, "\r\n") {
		return errors.New("the IPsec pre-shared key cannot contain line breaks")
	}
	switch s.AuthProto {
	case "", "auto", "mschapv2", "chap", "pap":
	default:
		return fmt.Errorf("unknown authentication protocol %q", s.AuthProto)
	}
	if s.Mtu != 0 && (s.Mtu < 576 || s.Mtu > 1500) {
		return fmt.Errorf("mtu %d is outside 576..1500", s.Mtu)
	}
	return nil
}

// Up dials the LNS and returns the ppp device Xray should bind egress to.
//
// Ordering is deliberate: IPsec (when a PSK is configured) is brought up and CONFIRMED
// before xl2tpd is started. With `start_action = start` charon installs the ESP policies
// only once the SA is up, so an xl2tpd that raced ahead would put the L2TP control
// channel, and the PPP authentication exchange inside it, on the wire in the clear.
func (d *l2tpOutDriver) Up(cfg VpnOutboundConfig) (string, error) {
	s, err := d.parse(cfg)
	if err != nil {
		return "", err
	}
	if err := d.Validate(cfg); err != nil {
		return "", err
	}
	name := l2tpOutSafeName(cfg.Tag)
	iface := l2tpOutIfName(cfg.Tag)

	// Idempotence. Up is called on save, at boot and by the reconciler, and the second
	// call on a live tunnel must not churn it: a redial would drop every connection
	// Xray currently has through this device.
	//
	// "Unchanged" is decided by a fingerprint of the settings stored in the generated
	// config, not by the tunnel merely being up. Returning early on a live-but-stale
	// tunnel is the subtle version of this bug: the operator changes the password, the
	// save reports success, and the daemon keeps running with the old one.
	if procMgr.IsRunning(l2tpOutProcName(name)) && l2tpOutStoredFingerprint(name) == l2tpOutFingerprint(s) {
		// The live device, not the one we asked for. pppd's rename is best effort (it
		// logs and carries on with pppN if SIOCSIFNAME fails), and insisting on the name
		// we wanted would redial a perfectly healthy tunnel on every reconcile.
		if got := l2tpOutResolveIface(name, iface); got != "" {
			return got, nil
		}
	}

	// Reap daemons orphaned by a previous panel that died without a clean shutdown.
	// Called before we start anything of our own because it pkills by binary path and
	// would otherwise take our own fresh instance with it.
	migrateFromSystemd()

	if err := l2tpOutEnsureBinaries(); err != nil {
		return "", err
	}

	// Resolve ONCE, here, and hand the same literal address to xl2tpd, to charon and to
	// the PSK's identity scope. A round-robin DNS name resolved separately by each of
	// them would have xl2tpd dialling one server while the ESP SA protects the path to
	// another, which fails as unexplained packet loss rather than as an error.
	peer, err := l2tpOutResolveV4(s.Server)
	if err != nil {
		return "", err
	}
	port := l2tpOutLocalPort(name)

	if s.IpsecPsk != "" {
		if err := d.ipsecUp(name, peer, port, s.IpsecPsk); err != nil {
			d.ipsecDown(name)
			return "", err
		}
	} else {
		// The operator cleared the PSK: drop any connection a previous save left in the
		// shared charon, or it would keep initiating to a peer we now talk to in plain.
		d.ipsecDown(name)
	}

	if err := d.writePppOptions(name, iface, s); err != nil {
		d.ipsecDown(name)
		return "", err
	}
	if err := d.writeXl2tpdConf(name, peer, port, s); err != nil {
		d.ipsecDown(name)
		return "", err
	}

	// xl2tpd refuses to start when its pid file names a live process. A stale file from
	// a killed panel whose pid has since been recycled is indistinguishable from that,
	// so it goes before every start.
	_ = os.Remove(l2tpOutPidFile(name))
	_ = os.MkdirAll(l2tpOutRunDir, 0755)

	args := []string{"-D", "-c", l2tpOutConfFile(name), "-p", l2tpOutPidFile(name), "-C", l2tpOutCtlFile(name)}
	if err := procMgr.Start(l2tpOutProcName(name), daemonBin("xl2tpd"), args, pppdEnv(), ""); err != nil {
		d.ipsecDown(name)
		return "", fmt.Errorf("start the l2tp client for %q: %w", cfg.Tag, err)
	}

	got, err := d.waitForIface(name, iface, l2tpOutDialTimeout)
	if err != nil {
		// Do not leave a dialling daemon behind: Save does not persist a config whose Up
		// failed, so nothing would ever stop it and the next panel restart would find an
		// xl2tpd it has no record of.
		_ = d.Down(cfg)
		return "", err
	}
	// Routing, the `oif` rule and BOTH halves of rp_filter belong to the framework
	// (vpnOutBindEgress, called on the way out of bringUp). The host-wide half matters
	// as much as the per-device one, because the kernel enforces the MAXIMUM of
	// conf.all and conf.<dev>, so relaxing only the device changes nothing on a host
	// that ships all=1.
	return got, nil
}

// Down stops the client instance and removes everything it installed. The egress rule
// and route are the framework's (vpnOutUnbindEgress runs on every teardown path it
// owns), so they are deliberately not touched here.
func (d *l2tpOutDriver) Down(cfg VpnOutboundConfig) error {
	name := l2tpOutSafeName(cfg.Tag)

	_ = procMgr.Stop(l2tpOutProcName(name))
	d.ipsecDown(name)

	_ = os.Remove(l2tpOutConfFile(name))
	_ = os.Remove(l2tpOutOptsFile(name))
	_ = os.Remove(l2tpOutPidFile(name))
	_ = os.Remove(l2tpOutCtlFile(name))
	// pppd removes its own device when it is signalled, so there is nothing to delete in
	// the kernel here. A leftover device would mean pppd survived, which procmgr's
	// process-group SIGTERM already covers (it is why xl2tpd runs in its own group).
	return nil
}

// Status reports whether the tunnel is actually carrying traffic.
func (d *l2tpOutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	name := l2tpOutSafeName(cfg.Tag)
	iface := l2tpOutResolveIface(name, l2tpOutIfName(cfg.Tag))
	if iface == "" {
		if procMgr.IsRunning(l2tpOutProcName(name)) {
			return false, "dialling"
		}
		return false, "down"
	}
	detail := iface
	if addr := l2tpOutIfaceAddr(iface); addr != "" {
		detail += " " + addr
	}
	// The IPsec leg can fail on its own (a rekey the peer refuses), and when it does the
	// ppp device stays up while every packet is dropped, so it has to be reported.
	if s, err := d.parse(cfg); err == nil && s.IpsecPsk != "" {
		if !l2tpOutIpsecEstablished(l2tpOutConnName(name)) {
			return false, detail + ", IPsec down"
		}
		detail += ", IPsec up"
	}
	return true, detail
}

// ---------------------------------------------------------------------------
// naming and paths
// ---------------------------------------------------------------------------

// l2tpOutSafeName reduces a tag to something usable as a filename, a procmgr key and
// part of a netdev name. Tags are operator input; only spaces are rejected upstream.
func l2tpOutSafeName(tag string) string {
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

func l2tpOutHash(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// l2tpOutIfName is the device name this tunnel's pppd is told to rename its unit to.
//
// Naming it ourselves is what makes the interface STABLE. Left alone, pppd takes the
// next free ppp<N>, so a redial after a peer timeout can come back on a different index
// while the stored VpnOutboundConfig.Iface (and therefore the freedom outbound Xray is
// running) still names the old one. That failure is invisible: the outbound stays in the
// config, binds a device that no longer exists or now belongs to an inbound client's
// session, and quietly egresses nothing or the wrong thing.
//
// 15 characters is the kernel's limit (IFNAMSIZ-1), so a long tag is truncated to three
// characters plus its hash rather than colliding with a neighbouring tag.
func l2tpOutIfName(tag string) string {
	safe := l2tpOutSafeName(tag)
	if len(safe) <= 11 {
		return "l2o-" + safe
	}
	return fmt.Sprintf("l2o-%.3s%08x", safe, l2tpOutHash(tag))
}

func l2tpOutProcName(name string) string { return "l2tp-out-" + name }
func l2tpOutConfFile(name string) string { return l2tpOutConfDir + "/" + name + ".conf" }
func l2tpOutOptsFile(name string) string { return "/etc/ppp/options.l2tp-out-" + name }
func l2tpOutPidFile(name string) string  { return l2tpOutRunDir + "/l2tp-out-" + name + ".pid" }
func l2tpOutCtlFile(name string) string  { return l2tpOutRunDir + "/l2tp-out-" + name + ".ctl" }

// l2tpOutLinkName is the pppd `linkname`, which decides the path of the pid file pppd
// writes for this link. It doubles as the ownership proof in l2tpOutResolveIface.
func l2tpOutLinkName(name string) string { return "l2tp-out-" + name }

// l2tpOutConnName is this tunnel's connection name in the SHARED charon. The prefix
// keeps it clear of the server side's namespaces: ikev2.go removes conf.d/ikev2-*.conf
// wholesale on every regenerate, l2tp.go owns exactly l2tp.conf and gre.go owns gre-*.
func l2tpOutConnName(name string) string { return "vpnout-l2tp-" + name }

func l2tpOutConnFile(name string) string {
	return swanctlConfDir + "/" + l2tpOutConnName(name) + ".conf"
}

// ---------------------------------------------------------------------------
// config generation
// ---------------------------------------------------------------------------

// l2tpOutEnsureBinaries extracts what this driver needs when the operator has never
// installed the L2TP core (an outbound-only box has no l2tp inbound, so the per-core
// provisioning that normally unpacks these never ran).
func l2tpOutEnsureBinaries() error {
	if backend.DaemonPath("xl2tpd") == "" && backend.Available() {
		if _, err := backend.ExtractOnly([]string{"xl2tpd"}); err != nil {
			logger.Warning("l2tp outbound: extract xl2tpd:", err)
		}
	}
	if backend.HasPppdBundle() {
		if _, err := os.Stat(backend.PppdBundled); err != nil {
			if err := backend.ExtractPppdBundle(); err != nil {
				logger.Warning("l2tp outbound: extract pppd bundle:", err)
			}
		}
		// xl2tpd execs the hard-coded /usr/sbin/pppd and pppd resolves plugins relative to
		// its compiled-in plugin dir, so both links have to exist. Both are no-ops when the
		// host has a pppd of its own.
		_ = backend.LinkSystemPppd()
		_ = backend.LinkPluginDir()
	}
	if bin := daemonBin("xl2tpd"); bin == "xl2tpd" {
		return errors.New("xl2tpd is not available on this host and is not bundled for this architecture")
	}
	return nil
}

// writePppOptions writes the pppd options file for this tunnel's calls.
//
// The two options that matter most are the two that keep the host's own networking out
// of the tunnel:
//
//   - nodefaultroute. An LNS hands its clients a default route, and pppd installs it by
//     default on many distributions (a distro /etc/ppp/options with `defaultroute` in it
//     is read before this file). Accepting it would move the HOST's traffic into the
//     tunnel: the panel's own outbound connections, the update checks, and the operator's
//     SSH session, which would drop the moment the tunnel came up and would not come
//     back, because the route that carried the session is gone. Egress through this
//     tunnel is opt-in per Xray outbound (SO_BINDTODEVICE plus the framework's private
//     routing table in vpnOutBindEgress), never a host-wide default.
//
//   - no usepeerdns. It writes the peer's resolvers into pppd's resolv.conf and hands
//     them to the distro's ip-up scripts, which on several distributions copy them into
//     the host's /etc/resolv.conf. The remote would then resolve names for the whole
//     panel, including its own control plane.
//
// The authentication options run the OPPOSITE way round from the server side, which is
// the easy mistake here: require-mschap-v2 and friends demand that the PEER authenticate
// itself to US, which is a thing an LNS never does and which fails every dial. What a
// client controls is which protocols it is willing to use to prove ITSELF, and that is
// the refuse-* family.
func (d *l2tpOutDriver) writePppOptions(name, iface string, s *l2tpOutSettings) error {
	mtu := s.Mtu
	if mtu == 0 {
		mtu = 1400
	}

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui (L2TP client outbound) - do not edit\n")
	// We are the client: the LNS does not authenticate itself to us.
	b.WriteString("noauth\n")
	// EAP is refused in every mode: pppd's EAP is an SRP/TLS implementation that no LNS
	// speaks in this role, and a server that offers it first would otherwise take us down
	// a path that can only fail.
	b.WriteString("refuse-eap\n")
	switch s.AuthProto {
	case "mschapv2":
		b.WriteString("refuse-pap\nrefuse-chap\nrefuse-mschap\n")
	case "chap":
		b.WriteString("refuse-pap\nrefuse-mschap\nrefuse-mschap-v2\n")
	case "pap":
		// PAP sends the password in the clear inside PPP. Acceptable only because the
		// operator asked for it, and normally paired with the IPsec leg.
		b.WriteString("refuse-chap\nrefuse-mschap\nrefuse-mschap-v2\n")
	default:
		// Anything the server offers except EAP. MS-CHAPv2 is what it will pick.
	}
	b.WriteString(fmt.Sprintf("user %s\n", l2tpOutQuote(s.Username)))
	b.WriteString(fmt.Sprintf("password %s\n", l2tpOutQuote(s.Password)))
	// Stable device name, and the link pid file that proves the device is ours.
	b.WriteString(fmt.Sprintf("ifname %s\n", iface))
	b.WriteString(fmt.Sprintf("linkname %s\n", l2tpOutLinkName(name)))
	b.WriteString(fmt.Sprintf("ipparam %s\n", l2tpOutLinkName(name)))
	// Take both addresses from the peer; we have no opinion about either.
	b.WriteString("noipdefault\n")
	b.WriteString("ipcp-accept-local\n")
	b.WriteString("ipcp-accept-remote\n")
	// No IPv6CP. The synthesized outbound binds one device and Xray egresses IPv4
	// through it; a negotiated IPv6 address would give the remote a second, unrouted
	// address family on the same link that nothing here manages.
	b.WriteString("noipv6\n")
	b.WriteString("nodefaultroute\n")
	b.WriteString(fmt.Sprintf("mtu %d\n", mtu))
	b.WriteString(fmt.Sprintf("mru %d\n", mtu))
	// Notice a peer that stops answering, so xl2tpd redials instead of leaving a device
	// up that silently drops everything Xray sends into it.
	b.WriteString("lcp-echo-interval 20\n")
	b.WriteString("lcp-echo-failure 3\n")

	if err := os.MkdirAll("/etc/ppp", 0755); err != nil {
		return err
	}
	// 0600: the file holds the account password.
	return os.WriteFile(l2tpOutOptsFile(name), []byte(b.String()), 0600)
}

// writeXl2tpdConf writes this tunnel's private xl2tpd config: a `[lac ...]` section,
// which is the client half of the daemon the server side already runs.
func (d *l2tpOutDriver) writeXl2tpdConf(name string, peer net.IP, port int, s *l2tpOutSettings) error {
	var b strings.Builder
	b.WriteString("; Auto-generated by vpn-ui (L2TP client outbound) - do not edit\n")
	// The fingerprint of the settings this file was generated from, so a later Up can
	// tell "already running" from "already running with what the operator just typed".
	b.WriteString(l2tpOutFingerprintMark + l2tpOutFingerprint(s) + "\n")
	b.WriteString("[global]\n")
	b.WriteString(fmt.Sprintf("port = %d\n", port))
	b.WriteString("access control = no\n\n")
	b.WriteString("[lac vpnout]\n")
	b.WriteString(fmt.Sprintf("lns = %s\n", peer.String()))
	b.WriteString(fmt.Sprintf("pppoptfile = %s\n", l2tpOutOptsFile(name)))
	// These three are set explicitly, and to the same answers the pppd options file
	// gives, because xl2tpd synthesises pppd arguments from them. Leaving them at their
	// defaults risks xl2tpd appending `auth` (demand that the LNS authenticate to us,
	// which no LNS does) on a command line that pppd processes after our options file,
	// where it would win.
	b.WriteString("require authentication = no\n")
	b.WriteString("require chap = no\n")
	b.WriteString("require pap = no\n")
	b.WriteString("length bit = yes\n")
	// Dial on start, and keep dialling. The panel only calls Up on save, at boot and on
	// reconcile, so without this a peer that is briefly unreachable stays down until
	// somebody presses something.
	b.WriteString("autodial = yes\n")
	b.WriteString("redial = yes\n")
	b.WriteString("redial timeout = 15\n")
	// Effectively unlimited. xl2tpd's `0` means different things in different releases,
	// and a wrong guess is a tunnel that gives up permanently after one bad afternoon.
	b.WriteString("max redials = 32767\n")

	if err := os.MkdirAll(l2tpOutConfDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(l2tpOutConfFile(name), []byte(b.String()), 0644)
}

// l2tpOutFingerprintMark introduces the settings fingerprint comment in the generated
// xl2tpd config. A comment, so xl2tpd itself ignores the line.
const l2tpOutFingerprintMark = "; vpn-ui-settings = "

// l2tpOutFingerprint hashes the operator's settings. Deliberately NOT including the
// resolved LNS address: a peer behind round-robin DNS would otherwise hand back a
// different answer on most reconciles and redial a perfectly healthy tunnel each time.
func l2tpOutFingerprint(s *l2tpOutSettings) string {
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%08x", l2tpOutHash(string(b)))
}

// l2tpOutStoredFingerprint reads back the fingerprint of the running config, or "".
func l2tpOutStoredFingerprint(name string) string {
	data, err := os.ReadFile(l2tpOutConfFile(name))
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(ln, l2tpOutFingerprintMark) {
			return strings.TrimSpace(strings.TrimPrefix(ln, l2tpOutFingerprintMark))
		}
	}
	return ""
}

// l2tpOutQuote renders a value for pppd's options parser, which understands
// double-quoted strings with backslash escapes.
func l2tpOutQuote(v string) string {
	esc := strings.ReplaceAll(v, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	return `"` + esc + `"`
}

// l2tpOutResolveV4 turns the configured LNS into a single IPv4 address.
func l2tpOutResolveV4(server string) (net.IP, error) {
	if ip := net.ParseIP(server); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("the LNS address %q is IPv6; the L2TP client is IPv4 only", server)
	}
	ips, err := net.LookupIP(server)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the LNS %q: %w", server, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("the LNS %q has no IPv4 address", server)
}

// l2tpOutLocalPort picks the UDP port this client instance binds.
//
// Deterministic from the tag so a redial of the same tunnel lands on the same port (the
// IPsec traffic selector names it), then walked forward if that port is taken, because
// two client tunnels hashing to the same number would otherwise leave the second one in
// a bind-failure restart loop.
func l2tpOutLocalPort(name string) int {
	first := int(l2tpOutHash(name) % l2tpOutPortSpan)
	for i := 0; i < l2tpOutPortSpan; i++ {
		p := l2tpOutPortBase + (first+i)%l2tpOutPortSpan
		if c, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", p)); err == nil {
			_ = c.Close()
			return p
		}
	}
	return l2tpOutPortBase + first
}

// ---------------------------------------------------------------------------
// interface discovery
// ---------------------------------------------------------------------------

// waitForIface blocks until this tunnel's ppp device is up and addressed.
func (d *l2tpOutDriver) waitForIface(name, want string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		if got := l2tpOutResolveIface(name, want); got != "" {
			return got, nil
		}
		if !procMgr.IsRunning(l2tpOutProcName(name)) {
			return "", fmt.Errorf("the l2tp client stopped before the link came up; see the %q log",
				l2tpOutProcName(name))
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("the l2tp link did not come up within %s; see the %q log",
				timeout, l2tpOutProcName(name))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// l2tpOutResolveIface returns the ppp device carrying THIS tunnel's session, or "".
//
// Naming the wrong device here is the worst failure this driver can have: the freedom
// outbound would bind SO_BINDTODEVICE to some other pppd's session, so this outbound's
// traffic would leave through an unrelated tunnel (or through an INBOUND client's link,
// billed to their account) and everything would look healthy. So the answer is proved,
// not guessed, in three steps:
//
//  1. pppd is told `ifname`, so the device it renames its unit to is decided by us. That
//     alone is not proof of ownership: the rename is best effort (pppd logs "Couldn't
//     rename interface" and carries on with pppN), and a device of that name could be
//     left over from a pppd that has since died.
//  2. pppd writes <rundir>/ppp-<linkname>.pid for the link we named with `linkname`: its
//     own pid on the first line, and the interface name on the second once the unit
//     exists. That file was written by OUR link's pppd.
//  3. pppd ALSO writes <rundir>/<ifname>.pid holding the pid of the pppd that owns that
//     device. Matching it against the pid from step 2 is what turns "a name in a file"
//     into proof, and it covers the case where the rename failed or the second line is
//     not there yet, because it can be searched across every ppp device on the box.
//
// The pid is checked for liveness first, so a stale file naming a device index the
// kernel has since handed to an INBOUND client's session cannot be claimed. Watching for
// "a new ppp device that appeared after we dialled" was the alternative and is rejected
// on exactly that point: it is a guess, and it guesses wrong precisely when the box is
// busy, which is when being wrong costs the most.
//
// A device only counts once it has an IPv4 address, i.e. once IPCP has finished: binding
// a socket to an addressless device gives it no source address, and the kernel then
// picks one from another interface, which the peer drops.
func l2tpOutResolveIface(name, want string) string {
	if pid, recorded := l2tpOutLinkPid(l2tpOutLinkName(name)); pid > 0 && l2tpOutProcessAlive(pid) {
		if recorded != "" && l2tpOutDevPid(recorded) == pid && l2tpOutIfaceReady(recorded) {
			return recorded
		}
		if owned := l2tpOutIfaceOwnedBy(pid); owned != "" && l2tpOutIfaceReady(owned) {
			return owned
		}
	}
	// No usable pid file (a distro pppd with a runtime directory we do not know about).
	// Fall back to the device we named ourselves, and only while our own daemon is alive:
	// nothing else on the box creates this name, and pppd removes its device when it
	// exits, so a device with our name under a running instance of ours is ours.
	if want != "" && l2tpOutIfaceReady(want) && procMgr.IsRunning(l2tpOutProcName(name)) {
		return want
	}
	return ""
}

// l2tpOutProcessAlive reports whether the pid exists. EPERM counts as alive: it means the
// process is there and owned by somebody else, which is still "not free to reuse".
func l2tpOutProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// l2tpOutRunDirs lists where a pppd might keep its pid files. The bundled pppd (2.5.x)
// uses /run/ppp; distro builds of 2.4.x use /var/run or /var/run/pppd. On most hosts
// /var/run is a symlink to /run, so the duplicates cost one failed stat.
var l2tpOutRunDirs = []string{"/run/ppp", "/var/run/ppp", "/run/pppd", "/var/run/pppd", "/run", "/var/run"}

// l2tpOutLinkPid reads <rundir>/ppp-<linkname>.pid: pppd's pid, and the interface name
// when that pppd has already created its unit.
func l2tpOutLinkPid(linkname string) (int, string) {
	for _, dir := range l2tpOutRunDirs {
		data, err := os.ReadFile(dir + "/ppp-" + linkname + ".pid")
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
		if err != nil {
			continue
		}
		iface := ""
		if len(lines) > 1 {
			iface = strings.TrimSpace(lines[1])
		}
		return pid, iface
	}
	return 0, ""
}

// l2tpOutIfaceOwnedBy finds the ppp-family device whose pppd has the given pid.
func l2tpOutIfaceOwnedBy(pid int) string {
	links, err := netlink.LinkList()
	if err != nil {
		return ""
	}
	for _, l := range links {
		dev := l.Attrs().Name
		if !strings.HasPrefix(dev, "ppp") && !strings.HasPrefix(dev, "l2o-") {
			continue
		}
		if l2tpOutDevPid(dev) == pid {
			return dev
		}
	}
	return ""
}

// l2tpOutDevPid reads <rundir>/<iface>.pid: the pid of the pppd that owns that device.
func l2tpOutDevPid(iface string) int {
	for _, dir := range l2tpOutRunDirs {
		data, err := os.ReadFile(dir + "/" + iface + ".pid")
		if err != nil {
			continue
		}
		if p, err := strconv.Atoi(strings.TrimSpace(strings.Split(string(data), "\n")[0])); err == nil {
			return p
		}
	}
	return 0
}

// l2tpOutIfaceReady reports whether the device exists and has finished IPCP.
func l2tpOutIfaceReady(iface string) bool { return l2tpOutIfaceAddr(iface) != "" }

// l2tpOutIfaceAddr returns the device's first IPv4 address, or "".
func l2tpOutIfaceAddr(iface string) string {
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
// host networking
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// the optional IPsec leg, on the SHARED charon
// ---------------------------------------------------------------------------

// ipsecUp adds this tunnel's IKEv1 transport connection to the shared charon and waits
// for the SA.
//
// Everything here is written so the daemon the SERVER side depends on is never disturbed:
//
//   - a file of our own under conf.d/, which swanctl.conf already includes with a glob,
//     so loading it is additive and no other protocol's file is touched;
//   - swanctl --load-all (reloadCharon), which merges every conf.d file and leaves live
//     SAs alone, rather than a restart;
//   - ensureCharonRunning rather than syncCharon, because syncCharon decides charon's
//     fate from the INBOUND table alone and would STOP the daemon on a box whose only
//     IPsec user is this outbound;
//   - /etc/strongswan.conf is written only when it does not exist yet. On a box that
//     already serves IKEv2 or L2TP/IPsec inbounds it belongs to them, and rewriting it
//     under a running charon buys nothing.
func (d *l2tpOutDriver) ipsecUp(name string, peer net.IP, port int, psk string) error {
	if !backend.HasStrongswanBundle() {
		return errors.New("L2TP/IPsec needs the bundled strongSwan, which is not available for this architecture; clear the pre-shared key to dial plain L2TP")
	}
	if !ikev2OutFileExists("/etc/strongswan.conf") || !ikev2OutFileExists(swanctlDir+"/swanctl.conf") {
		// swanctl.conf matters as much as strongswan.conf: it is the `include
		// conf.d/*.conf` line, without which our connection file is never read at all.
		if err := writeCharonConf(); err != nil {
			return fmt.Errorf("write the shared charon config: %w", err)
		}
	}
	_ = os.MkdirAll(swanctlConfDir, 0755)
	if err := d.writeSwanctlConn(name, peer, port, psk); err != nil {
		return err
	}
	if err := ensureCharonRunning(); err != nil {
		return err
	}
	if err := reloadCharon(); err != nil {
		return err
	}

	conn := l2tpOutConnName(name)
	deadline := time.Now().Add(l2tpOutIpsecTimeout)
	for {
		if l2tpOutIpsecEstablished(conn) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the IPsec SA to %s did not establish within %s; check the pre-shared key and that UDP 500/4500 reach the peer",
				peer, l2tpOutIpsecTimeout)
		}
		time.Sleep(time.Second)
	}
}

// ipsecDown terminates and unloads this tunnel's connection. The reload is skipped when
// charon is not running, so panel shutdown does not log a failed vici connect per tunnel.
func (d *l2tpOutDriver) ipsecDown(name string) {
	conn := l2tpOutConnName(name)
	if procMgr.IsRunning(ikev2ProcName) {
		// --timeout, because a bare --terminate WAITS for the delete exchange to complete
		// and an unreachable peer makes charon retransmit for the best part of a minute.
		// Down runs on panel shutdown, once per tunnel, in series.
		_ = exec.Command(swanctlBin(), "--terminate", "--ike", conn, "--timeout", "5").Run()
	}
	if _, err := os.Stat(l2tpOutConnFile(name)); err != nil {
		return
	}
	_ = os.Remove(l2tpOutConnFile(name))
	if procMgr.IsRunning(ikev2ProcName) {
		// --load-all also unloads connections that are no longer in any conf.d file, which
		// is what actually removes ours. Other protocols' connections are reloaded from
		// their own files in the same pass and keep their SAs.
		_ = reloadCharon()
	}
}

// writeSwanctlConn writes the IKEv1 transport connection protecting this client's L2TP.
func (d *l2tpOutDriver) writeSwanctlConn(name string, peer net.IP, port int, psk string) error {
	esc := strings.ReplaceAll(psk, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	conn := l2tpOutConnName(name)

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui (L2TP client outbound, IKEv1 transport on the shared charon) - do not edit\n")
	b.WriteString("connections {\n")
	b.WriteString(fmt.Sprintf("    %s {\n", conn))
	// IKEv1: L2TP/IPsec is an IKEv1 protocol everywhere it is deployed, and the shared
	// charon is pinned to a 5.x release precisely because 6.x dropped IKEv1.
	b.WriteString("        version = 1\n")
	b.WriteString(fmt.Sprintf("        remote_addrs = %s\n", peer.String()))
	b.WriteString("        aggressive = no\n")
	b.WriteString("        mobike = no\n")
	b.WriteString("        rekey_time = 3h\n")
	b.WriteString("        reauth_time = 0s\n")
	b.WriteString("        dpd_delay = 30s\n")
	b.WriteString("        fragmentation = yes\n")
	// A wide list because we are the initiator and the far end is whatever the operator
	// happens to be renting: consumer boxes and older enterprise gear answer a narrow
	// modern proposal with NO_PROPOSAL_CHOSEN.
	b.WriteString("        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,3des-sha1-modp2048,aes256-sha1-modp1536,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024,default\n")
	b.WriteString("        local {\n            auth = psk\n        }\n")
	// No remote id. In IKEv1 Main Mode the pre-shared key has to be chosen BEFORE the
	// identities are exchanged (SKEYID is derived from it), so charon selects it by
	// ADDRESS, which is what the secret below is scoped to. Pinning an expected IDr on
	// top of that only adds a way to fail: an LNS may present its FQDN, its certificate
	// subject or its address, and refusing the exchange over the label a peer chose for
	// itself buys nothing when the key is the credential and remote_addrs already pins
	// who we are talking to.
	b.WriteString("        remote {\n            auth = psk\n        }\n")
	b.WriteString("        children {\n")
	b.WriteString("            l2tp {\n")
	b.WriteString("                mode = transport\n")
	// The selectors name OUR port, not 1701, because the server instance owns 1701 on
	// this host. `dynamic` resolves to whichever local address the SA lands on.
	b.WriteString(fmt.Sprintf("                local_ts = dynamic[udp/%d]\n", port))
	b.WriteString(fmt.Sprintf("                remote_ts = %s/32[udp/1701]\n", peer.String()))
	b.WriteString("                esp_proposals = aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1,default\n")
	b.WriteString("                rekey_time = 1h\n")
	// We initiate, and we re-initiate: this is a client, so a peer that goes away should
	// be dialled again rather than left for a human.
	b.WriteString("                start_action = start\n")
	b.WriteString("                dpd_action = restart\n")
	b.WriteString("                close_action = restart\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	b.WriteString("secrets {\n")
	b.WriteString(fmt.Sprintf("    ike-%s {\n", conn))
	// TWO owners, for the reason greipsec.go documents at length: strongSwan matches a
	// pre-shared key by looking up an owner for BOTH ends, so a secret listing only one
	// identity never matches and charon falls back to another connection's owner-less key
	// (the L2TP server writes one) and signs with the wrong secret. Naming the peer plus
	// %any matches this pair and beats the owner-less key on specificity, so our key is
	// chosen here and is not offered to an inbound peer.
	b.WriteString(fmt.Sprintf("        id_remote = %s\n", peer.String()))
	b.WriteString("        id_any = %any\n")
	b.WriteString(fmt.Sprintf("        secret = \"%s\"\n", esc))
	b.WriteString("    }\n")
	b.WriteString("}\n")

	return os.WriteFile(l2tpOutConnFile(name), []byte(b.String()), 0600)
}

// l2tpOutIpsecEstablished reports whether the named connection has a live IKE SA with an
// installed child. Both halves matter: an ESTABLISHED IKE SA whose child was never
// installed protects nothing, and that is exactly the state a traffic-selector mismatch
// with the peer leaves behind.
// --noblock, always: `swanctl --list-sas` otherwise WAITS on any IKE_SA that is checked
// out, and on this shared charon that includes an inbound IKEv2 client sitting
// mid-authentication against the panel's own RADIUS server. ikev2.go documents the same
// hazard from the other direction. This call runs inside the panel's save handler, so a
// blocking listing would stall an HTTP request behind an unrelated client's login.
func l2tpOutIpsecEstablished(conn string) bool {
	out, err := exec.Command(swanctlBin(), "--list-sas", "--noblock", "--ike", conn).CombinedOutput()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "ESTABLISHED") && strings.Contains(s, "INSTALLED")
}
