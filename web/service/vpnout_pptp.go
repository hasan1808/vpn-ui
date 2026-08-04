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

// PPTP as an OUTBOUND: the panel dials somebody else's PPTP server as a client and
// Xray egresses through the ppp device that comes up.
//
// The server side (pptp.go) runs pptpd, which is a different project entirely and has
// no client mode, so this file drives the OTHER bundled binary: `pptp` (pptpclient),
// which speaks the PPTP control channel on TCP 1723 and carries PPP inside GRE.
//
// The process tree is inverted from what the name suggests. pptp is NOT the parent:
//
//	pppd  pty "<pptp> <server> --nolaunchpppd"  file <options>   <- the procmgr child
//	  \_ pptp                                                    <- the pty helper
//
// pppd owns the link, so pppd is what procmgr supervises, and pptp is spawned by pppd
// as the "modem" behind a pseudo-terminal. That ordering is what makes it possible to
// choose WHICH pppd runs (this matters much more for the SSTP twin, see
// vpnout_sstp.go) and to keep every credential out of the process list: the secrets
// live in a 0600 options file, and the only thing on the command line is the server
// address.
//
// This file also carries the pppOut* helpers, which vpnout_sstp.go shares. Both
// drivers are the same shape (a pppd behind a pty helper) and the hard part of both,
// proving WHICH ppp device belongs to this tunnel, is one problem with one answer;
// two copies of it would be two places for a subtle ownership bug to live. Nothing
// else in the package uses them.
const (
	// pptpOutIfPrefix names the client's ppp devices. Nothing else on the box creates
	// this name: the PPTP SERVER's sessions are plain pppN (pptpd never renames), and
	// the L2TP client uses l2o-.
	pptpOutIfPrefix = "pptpo-"

	// pppOutIfMax is IFNAMSIZ-1: 16 bytes including the NUL. pppd passes the name to
	// SIOCSIFNAME, which simply refuses anything longer, and pppd then carries on with
	// the kernel's own pppN. Shared with the SSTP driver.
	pppOutIfMax = 15

	// pptpOutDialTimeout bounds the wait for the link. It is a boot cost as well as a
	// save cost, because InitVpnOutbound raises tunnels one at a time before Xray
	// starts, so an unreachable server delays the whole panel by this much. PPTP has no
	// TLS handshake and no key exchange worth the name, so a working server is up in
	// two or three seconds; this is sized for a distant one.
	pptpOutDialTimeout = 30 * time.Second
	pppOutPoll         = 500 * time.Millisecond

	// pppOutFingerprintMark introduces the settings fingerprint in a generated pppd
	// options file. A `#` comment, so pppd's option parser skips it.
	pppOutFingerprintMark = "# vpn-ui-settings = "
)

// pptpOutSettings is the PPTP slice of one outbound tunnel's opaque Settings blob.
type pptpOutSettings struct {
	Server   string `json:"server"`   // PPTP server hostname or IPv4 address
	Username string `json:"username"` // PPP username
	Password string `json:"password"` // PPP password

	// AuthProto pins which protocol we are willing to prove OURSELVES with:
	// "" / "auto" (anything but EAP), "mschapv2" (the default and what every PPTP
	// server speaks), "mschap", "chap" or "pap".
	AuthProto string `json:"authProto"`

	// Mppe is "" or "required" for require-mppe-128, or "off" to drop encryption.
	// PPTP without MPPE is a cleartext tunnel, and it is also the only combination in
	// which PAP or CHAP can be used at all, because the MPPE session keys are derived
	// from the MS-CHAP exchange and nothing else produces them.
	Mppe string `json:"mppe"`

	Mtu int `json:"mtu"`
}

type pptpOutDriver struct{}

var _ VpnOutSecrets = (*pptpOutDriver)(nil)

func init() { RegisterVpnOutDriver(VpnOutPPTP, &pptpOutDriver{}) }

// SecretKeys keeps the PPP password off the wire to the browser.
//
// Without this the whole settings blob went to /vpnoutbound/list as stored, so every
// page load of the Xray settings shipped the account password of every PPTP tunnel in
// cleartext to anyone who could open the panel. The form never showed it (the model
// refuses to seed a field marked `secret`), which is exactly what made it invisible:
// the box looked empty while the response behind it carried the password.
//
// Only the password. `server`, `username`, `authProto` and `mppe` are what an operator
// checks first when a tunnel will not authenticate, and hiding them would cost real
// diagnosis for no secrecy.
func (d *pptpOutDriver) SecretKeys() []string { return []string{"password"} }

func (d *pptpOutDriver) parse(cfg VpnOutboundConfig) (*pptpOutSettings, error) {
	s := &pptpOutSettings{}
	if len(cfg.Settings) > 0 {
		if err := json.Unmarshal(cfg.Settings, s); err != nil {
			return nil, fmt.Errorf("pptp outbound %q: unreadable settings: %w", cfg.Tag, err)
		}
	}
	s.Server = strings.TrimSpace(s.Server)
	s.Username = strings.TrimSpace(s.Username)
	s.AuthProto = strings.ToLower(strings.TrimSpace(s.AuthProto))
	s.Mppe = strings.ToLower(strings.TrimSpace(s.Mppe))
	return s, nil
}

// Available reports whether a PPTP outbound can run here at all.
//
// The answer comes from the bundle manifest rather than from a probe, because
// //go:embed uses `all:bin` and a client that was never built for this architecture is
// a runtime fact, not a build one. Asked at SAVE time, so it must not extract
// anything (see backend.EnsureClients, which Up calls instead).
//
// The two halves need DIFFERENT advice and must not be given one message. The client
// is bundle-only, so nothing an operator installs produces it; pppd is not, because
// pptpOutPppdBinary falls back to a host one, so naming the distribution package there
// is real advice rather than a shrug.
func (d *pptpOutDriver) Available() (bool, string) {
	if ok, why := backend.ClientAvailable(backend.PptpClient); !ok {
		return false, why + ". No package or core supplies it: the driver runs the bundled client only, " +
			"so this needs a vpn-ui build for " + runtime.GOARCH
	}
	// pptp is only the control channel; the PPP session, the authentication and the
	// MPPE keys are all pppd's. A host with neither a bundled nor an installed pppd
	// can dial the server and will then have nothing to hand the call to.
	if !backend.HasPppdBundle() && !commandExists("pppd") {
		return false, "there is no pppd here to run the PPP session the PPTP client sets up: " +
			"this build carries no pppd bundle for " + runtime.GOARCH + ", so install your distribution's " +
			"ppp package, which this driver will use"
	}
	return true, ""
}

// Validate refuses a config while the modal is still open. Everything decidable
// without touching the network is decided here: the alternative is a thirty second
// wait ending in a timeout that explains nothing.
func (d *pptpOutDriver) Validate(cfg VpnOutboundConfig) error {
	s, err := d.parse(cfg)
	if err != nil {
		return err
	}
	if s.Server == "" {
		return errors.New("the PPTP server address is required")
	}
	if s.Username == "" {
		return errors.New("a PPP username is required")
	}
	if s.Password == "" {
		// Not a configuration anybody wants: it is what a half-filled form produces,
		// and it fails at authentication inside a daemon log nobody is watching.
		return errors.New("a PPP password is required")
	}
	// The credentials are written into a pppd options file, whose parser is line
	// oriented: a newline would forge an option rather than be part of the value.
	if strings.ContainsAny(s.Username+s.Password, "\r\n") {
		return errors.New("the username and password cannot contain line breaks")
	}
	switch s.AuthProto {
	case "", "auto", "mschapv2", "mschap", "chap", "pap":
	default:
		return fmt.Errorf("unknown authentication protocol %q", s.AuthProto)
	}
	switch s.Mppe {
	case "", "required", "off":
	default:
		return fmt.Errorf("mppe must be %q or %q, not %q", "required", "off", s.Mppe)
	}
	// MPPE keys are a by-product of MS-CHAP. Asking for encryption while refusing the
	// only authentication that can produce a key is a config pppd accepts and then
	// fails to bring up, with a message ("MPPE required but peer negotiation failed")
	// that names the symptom rather than this contradiction.
	if s.Mppe != "off" && (s.AuthProto == "pap" || s.AuthProto == "chap") {
		return fmt.Errorf("MPPE encryption cannot be used with %s authentication: the session keys are "+
			"derived from MS-CHAP, so choose mschapv2, or set mppe to off and accept an unencrypted tunnel",
			strings.ToUpper(s.AuthProto))
	}
	if s.Mtu != 0 && (s.Mtu < 576 || s.Mtu > 1500) {
		return fmt.Errorf("mtu %d is outside 576..1500", s.Mtu)
	}
	return nil
}

// Up dials the server and returns the ppp device Xray should bind egress to.
func (d *pptpOutDriver) Up(cfg VpnOutboundConfig) (string, error) {
	s, err := d.parse(cfg)
	if err != nil {
		return "", err
	}
	if err := d.Validate(cfg); err != nil {
		return "", err
	}
	name := pppOutSafeName(cfg.Tag)
	iface := pptpOutIfName(cfg.Tag)
	proc := pptpOutProcName(name)
	opts := pptpOutOptsFile(name)

	// Idempotence, which Up is required to have: it is called on save, at boot and on
	// every reconcile, and a redial would drop every connection Xray currently holds
	// through this device.
	//
	// "Already up" is decided by the fingerprint of the settings stored in the
	// generated options file, never by the tunnel merely being alive. Returning early
	// on a live-but-stale tunnel is the subtle version of this bug: the operator
	// changes the password, the save reports success, and pppd keeps running the old
	// one until something unrelated restarts it.
	//
	// The LIVE device is returned, not the one we asked for. pppd's rename is best
	// effort and the device index moves on every redial, so insisting on the name we
	// wanted would either churn a healthy tunnel or hand back a stale answer.
	if procMgr.IsRunning(proc) && pppOutStoredFingerprint(opts) == pppOutFingerprintOf(s) {
		if got := pppOutResolveIface(pptpOutLinkName(name), iface, proc); got != "" {
			return got, nil
		}
	}

	// The binaries are embedded, and nothing else in the panel lays the client-side
	// ones down: no core owns them, so without this they never reach disk.
	if err := backend.EnsureClients(); err != nil {
		return "", fmt.Errorf("could not unpack the bundled VPN clients: %w", err)
	}
	pptpBin := backend.ClientPath(backend.PptpClient)
	if pptpBin == "" {
		return "", errors.New("the pptp client is not on disk and is not bundled for this architecture")
	}
	pppd, err := pptpOutPppdBinary()
	if err != nil {
		return "", err
	}

	// Reap daemons orphaned by a panel that died without a clean shutdown. Run before
	// our own child exists because it pkills by binary path and would otherwise be
	// free to fire later (the first time an operator adds an inbound) and shoot this
	// client down mid-session.
	migrateFromSystemd()

	// ppp_mppe is the one that is easy to miss: without it pppd negotiates MPPE, fails
	// to install it, and drops the link with "MPPE required but kernel has no support".
	for _, mod := range []string{"ppp_generic", "ppp_async", "ppp_mppe"} {
		_ = exec.Command("modprobe", mod).Run()
	}

	// Resolve ONCE and hand pptp a literal. A server behind round-robin DNS resolved
	// separately by each redial would otherwise wander between hosts, and a name that
	// does not resolve at all is worth catching here rather than inside a pty helper
	// whose stderr may not reach the log.
	peer, err := pppOutResolveV4(s.Server, "PPTP server")
	if err != nil {
		return "", err
	}

	if err := d.writeOptions(name, iface, pppd, s); err != nil {
		return "", err
	}

	// The ring buffer survives a restart under the same process name, so the wait below
	// has to know where THIS attempt's output begins. Without that a stale
	// authentication failure from the run that made the operator fix their password
	// would fail the very save that fixed it.
	logMark := pppOutLogLines(procMgr.Logs(proc))

	args := []string{
		"file", opts,
		// pppd hands this string to /bin/sh, so the paths inside it are quoted. They
		// are ours and contain no spaces today, which is exactly the assumption worth
		// not baking in.
		"pty", fmt.Sprintf("%s %s --nolaunchpppd --nohostroute --logstring %s",
			pppOutShellQuote(pptpBin), pppOutShellQuote(peer.String()), pppOutShellQuote(pptpOutLinkName(name))),
		// Foreground, or procmgr supervises a parent that forks and exits immediately
		// and then restarts it every five seconds forever.
		"nodetach",
		// Named here rather than only in the options file so the procmgr log line says
		// which tunnel and which device this invocation is.
		"ifname", iface,
		"linkname", pptpOutLinkName(name),
		"ipparam", pptpOutLinkName(name),
	}
	if err := procMgr.Start(proc, pppd, args, pppdEnv(), ""); err != nil {
		return "", fmt.Errorf("start the pptp client for %q: %w", cfg.Tag, err)
	}

	got, err := d.waitForIface(name, iface, proc, logMark)
	if err != nil {
		// Do not leave a dialling pppd behind. Save does not persist a config whose Up
		// failed, so nothing would ever stop it: the panel would report the save as
		// failed while a process kept retrying against a server the operator has
		// already given up on.
		_ = d.Down(cfg)
		return "", err
	}
	return got, nil
}

// Down stops the client and removes what it wrote. Tolerates a tunnel that is already
// gone, which is what a panel restart between a failed Up and the next reconcile
// leaves behind.
func (d *pptpOutDriver) Down(cfg VpnOutboundConfig) error {
	name := pppOutSafeName(cfg.Tag)
	// procmgr signals the whole process group, which is why pptp (pppd's pty child)
	// goes with it. pppd removes its own device and its pid files on the way out, so
	// there is nothing in the kernel to delete here; a device that survived would mean
	// pppd did not, and the group SIGKILL in procmgr's shutdown path covers that.
	_ = procMgr.Stop(pptpOutProcName(name))
	// The file holds the account password in clear and Up rewrites every byte of it,
	// so there is nothing to keep and a reason not to.
	_ = os.Remove(pptpOutOptsFile(name))
	return nil
}

// Status reports the two halves of "is this working" separately, because they come
// apart in practice: a pppd that is retrying is alive every five seconds and has no
// device, and a pppd whose peer vanished can hold a device that carries nothing.
func (d *pptpOutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	name := pppOutSafeName(cfg.Tag)
	proc := pptpOutProcName(name)
	running := procMgr.IsRunning(proc)
	iface := pppOutResolveIface(pptpOutLinkName(name), pptpOutIfName(cfg.Tag), proc)

	logs := procMgr.Logs(proc)
	if iface == "" {
		if tell := pptpOutLogTell(logs); tell != "" {
			return false, tell + "\n" + pppOutLastLines(logs, 5)
		}
		if running {
			return false, "dialling"
		}
		return false, "down"
	}

	parts := []string{iface}
	if addr := pppOutIfaceAddr(iface); addr != "" {
		parts = append(parts, "address "+addr)
	}
	if link, err := netlink.LinkByName(iface); err == nil {
		if st := link.Attrs().Statistics; st != nil {
			parts = append(parts, fmt.Sprintf("rx %s, tx %s", pppOutBytes(st.RxBytes), pppOutBytes(st.TxBytes)))
		}
	}
	if !running {
		// The device outliving its pppd means the process was killed without being able
		// to clean up. Traffic pinned to it is going nowhere.
		parts = append(parts, "CLIENT STOPPED")
	}
	return running, strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// naming and paths
// ---------------------------------------------------------------------------

// pptpOutIfName maps a tag to a bounded, deterministic device name.
//
// Deterministic because Down and Status are handed nothing but the stored config and
// have to find the same link; bounded because the kernel refuses anything longer than
// IFNAMSIZ-1. A tag that is already a legal short name is kept readable so `ip -s
// link` means something to a human, and the dash separator keeps the two forms in
// disjoint namespaces so a hashed name can never land on a readable one.
func pptpOutIfName(tag string) string {
	safe := pppOutSafeName(tag)
	if len(safe) <= pppOutIfMax-len(pptpOutIfPrefix) {
		return pptpOutIfPrefix + safe
	}
	return fmt.Sprintf("%s%08x", strings.TrimSuffix(pptpOutIfPrefix, "-"), pppOutHash(tag))
}

// pptpOutProcName is the procmgr key. The prefix keeps it clear of the server side,
// which owns exactly "pptpd" (PptpService.RestartServices/StopServices).
func pptpOutProcName(name string) string { return "pptp-out-" + name }

// pptpOutLinkName is the pppd `linkname`, which decides the path of the per-link pid
// file pppd writes. It is also the ownership proof in pppOutResolveIface, so it has to
// be unique per tunnel and stable across redials.
func pptpOutLinkName(name string) string { return "pptp-out-" + name }

// pptpOutOptsFile is this tunnel's pppd options file. Beside the L2TP client's, whose
// naming convention it follows, and clear of /etc/ppp/pptpd-options, which the SERVER
// regenerates from the inbound table.
func pptpOutOptsFile(name string) string { return "/etc/ppp/options.pptp-out-" + name }

// ---------------------------------------------------------------------------
// the pppd to run
// ---------------------------------------------------------------------------

// pptpOutPppdBinary resolves the pppd that will own the link.
//
// Unlike the SSTP twin, PPTP has no musl-only plugin to load, so a distro pppd is a
// perfectly good host for the session and is preferred wherever one exists: that is
// the same rule the server side follows (backend.UsingBundledPppd), and shadowing a
// distro pppd would change which OpenSSL providers MS-CHAP and MPPE resolve against.
func pptpOutPppdBinary() (string, error) {
	if backend.HasPppdBundle() {
		if _, err := os.Stat(backend.PppdBundled); err != nil {
			if err := backend.ExtractPppdBundle(); err != nil {
				logger.Warning("pptp outbound: extract the pppd bundle:", err)
			}
		}
		// Both links are no-ops when the host has a pppd of its own. They matter when it
		// does not: pppd resolves a bare `plugin` name against its compiled-in plugin
		// directory, and other daemons on this box exec the hard-coded /usr/sbin/pppd.
		_ = backend.LinkSystemPppd()
		_ = backend.LinkPluginDir()
	}
	if backend.UsingBundledPppd() {
		if _, err := os.Stat(backend.PppdBundled); err == nil {
			return backend.PppdBundled, nil
		}
	}
	if p, err := exec.LookPath("pppd"); err == nil {
		return p, nil
	}
	if _, err := os.Stat(backend.PppdSystem); err == nil {
		return backend.PppdSystem, nil
	}
	if _, err := os.Stat(backend.PppdBundled); err == nil {
		return backend.PppdBundled, nil
	}
	return "", errors.New("no pppd on this host and none bundled for this architecture, so the PPTP client has nothing to run the PPP session")
}

// ---------------------------------------------------------------------------
// the options file
// ---------------------------------------------------------------------------

// writeOptions renders the pppd options file for this tunnel.
//
// Two of these options are the whole reason this driver does not take the host off the
// network, and both run the opposite way from the server side, which is the easy
// mistake here:
//
//   - nodefaultroute. A PPTP server hands its clients a default route, and pppd
//     installs one by default (a distro /etc/ppp/options carrying `defaultroute` is
//     read before this file, so saying nothing is not the same as saying no). Taking
//     it would move the HOST into somebody else's tunnel: the panel's own listener,
//     its update checks, the operator's SSH session, and the tunnel's own outer GRE,
//     which then loops. Egress through this tunnel is opt-in per Xray outbound
//     (SO_BINDTODEVICE plus the private table vpnOutBindEgress installs) and is never
//     host-wide.
//
//   - no usepeerdns, ever. It writes the peer's resolvers into pppd's resolv.conf and
//     hands them to /etc/ppp/ip-up, which on several distributions copies them into
//     the host's /etc/resolv.conf. The remote would then resolve names for the whole
//     panel, including its own control plane. pppd has no way to turn usepeerdns back
//     OFF once a distro /etc/ppp/options has turned it on, so where the pppd is known
//     to be recent enough the ip-up/ip-down scripts are pointed at /bin/true instead,
//     which also stops any other distro hook from touching this link.
//
// The authentication options are the other inversion: require-mschap-v2 and its
// relatives demand that the PEER prove itself to US, which no PPTP server does and
// which fails every dial. What a client controls is which protocols it will use to
// prove ITSELF, and that is the refuse-* family.
func (d *pptpOutDriver) writeOptions(name, iface, pppd string, s *pptpOutSettings) error {
	mtu := s.Mtu
	if mtu == 0 {
		// The same default the PPTP server side uses. PPP inside GRE inside IP leaves
		// well under 1500, and a too-large MTU here shows up as large transfers hanging
		// while pings work.
		mtu = 1400
	}

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui (PPTP client outbound) - do not edit\n")
	b.WriteString(pppOutFingerprintMark + pppOutFingerprintOf(s) + "\n")

	// We are the client: the server does not authenticate itself to us.
	b.WriteString("noauth\n")
	// pppd's EAP is an SRP/TLS implementation no PPTP server speaks, and a server that
	// offers it first would take us down a path that can only fail.
	b.WriteString("refuse-eap\n")
	switch s.AuthProto {
	case "mschap":
		b.WriteString("refuse-pap\nrefuse-chap\nrefuse-mschap-v2\n")
	case "chap":
		b.WriteString("refuse-pap\nrefuse-mschap\nrefuse-mschap-v2\n")
	case "pap":
		// PAP sends the password in the clear inside PPP, and PPTP has no outer
		// encryption to hide it. Only reachable when MPPE is off, which Validate makes
		// the operator ask for explicitly.
		b.WriteString("refuse-chap\nrefuse-mschap\nrefuse-mschap-v2\n")
	case "auto":
		// Anything but EAP. In practice the server picks MS-CHAPv2.
	default: // "" and "mschapv2"
		b.WriteString("refuse-pap\nrefuse-chap\nrefuse-mschap\n")
	}
	if s.Mppe == "off" {
		b.WriteString("nomppe\n")
	} else {
		// require-mppe-128 and not plain require-mppe: the plain form accepts 40-bit,
		// which is not encryption in any sense worth having.
		b.WriteString("require-mppe-128\n")
		// MPPE is a stream cipher over the PPP payload and cannot be combined with
		// stateful compression; pppd would negotiate both and then drop every frame.
		b.WriteString("nobsdcomp\nnodeflate\nnovj\nnovjccomp\n")
	}
	b.WriteString(fmt.Sprintf("name %s\n", pppOutQuote(s.Username)))
	b.WriteString(fmt.Sprintf("password %s\n", pppOutQuote(s.Password)))
	// Stable device name and the per-link pid file that proves the device is ours. Also
	// on the command line, and deliberately in both places: a distro /etc/ppp/options
	// cannot override either, and the file is what Down and Status read back.
	b.WriteString(fmt.Sprintf("ifname %s\n", iface))
	b.WriteString(fmt.Sprintf("linkname %s\n", pptpOutLinkName(name)))
	b.WriteString(fmt.Sprintf("ipparam %s\n", pptpOutLinkName(name)))
	// Take both addresses from the peer; we have no opinion about either.
	b.WriteString("noipdefault\nipcp-accept-local\nipcp-accept-remote\n")
	// No IPv6CP. The synthesized outbound binds one device and Xray egresses IPv4
	// through it, so a negotiated IPv6 address would be a second, unrouted address
	// family on the same link that nothing here manages.
	b.WriteString("noipv6\n")
	b.WriteString("nodefaultroute\n")
	// A pty is not a tty: locking it would try to create a UUCP lock file for a device
	// that does not exist, and a distro /etc/ppp/options carrying `lock` is common.
	b.WriteString("nolock\n")
	b.WriteString(fmt.Sprintf("mtu %d\nmru %d\n", mtu, mtu))
	// Notice a peer that stops answering. PPTP carries data in GRE, which is
	// connectionless, so without echoes a dead server looks exactly like an idle one
	// and the device stays up swallowing everything Xray sends into it.
	b.WriteString("lcp-echo-interval 20\nlcp-echo-failure 3\n")
	// Redial in-process rather than dying and waiting for procmgr's five second
	// restart, and never give up: this is a client whose peer is somebody else's
	// server, so a bad afternoon must not need a human to undo.
	b.WriteString("persist\nmaxfail 0\nholdoff 10\n")
	// Log to stdout so procmgr's ring buffer captures it. Without this pppd logs only
	// to syslog and the panel's "Logs" view for this tunnel is empty, which is the
	// difference between diagnosing a rejected password and guessing at one.
	b.WriteString("logfd 1\n")

	if pppd == backend.PppdBundled {
		// Only for the pppd this project builds (ppp 2.5.x), because ip-up-script and
		// ip-down-script did not exist before 2.5 and an unknown option is fatal to
		// pppd. /bin/true is a real, harmless program, so pppd runs it, gets 0 and
		// moves on; the point is that the DISTRO's /etc/ppp/ip-up (and its ip-up.d
		// directory) never runs for this link, which is what stops a third-party hook
		// rewriting resolv.conf or installing routes behind the panel's back.
		b.WriteString("ip-up-script /bin/true\nip-down-script /bin/true\n")
	}

	if err := os.MkdirAll("/etc/ppp", 0755); err != nil {
		return err
	}
	// 0600: the file holds the account password.
	return os.WriteFile(pptpOutOptsFile(name), []byte(b.String()), 0600)
}

// ---------------------------------------------------------------------------
// bringing the link up
// ---------------------------------------------------------------------------

// waitForIface blocks until this tunnel's ppp device exists and has finished IPCP.
//
// The log is read in parallel, because the failures that matter most (a rejected
// password, a server that refuses MPPE, a blocked control port) never produce a device
// at all: waiting the full timeout to report "it did not appear" throws away the one
// line that says why, and `persist` means pppd will keep retrying that same failure
// for as long as anyone is willing to watch.
func (d *pptpOutDriver) waitForIface(name, want, proc string, logMark int) (string, error) {
	deadline := time.Now().Add(pptpOutDialTimeout)
	for {
		if got := pppOutResolveIface(pptpOutLinkName(name), want, proc); got != "" {
			return got, nil
		}
		fresh := pppOutLogSince(procMgr.Logs(proc), logMark)
		if tell := pptpOutLogTell(fresh); tell != "" {
			return "", fmt.Errorf("the pptp client did not connect: %s", tell)
		}
		if !procMgr.IsRunning(proc) {
			return "", fmt.Errorf("the pptp client stopped before the link came up:\n%s",
				pppOutLastLines(fresh, 6))
		}
		if time.Now().After(deadline) {
			last := pppOutLastLines(fresh, 6)
			if last == "" {
				last = "no output from the client"
			}
			return "", fmt.Errorf("the PPTP link did not come up within %s. Last log:\n%s",
				pptpOutDialTimeout, last)
		}
		time.Sleep(pppOutPoll)
	}
}

// pptpOutLogTell turns the handful of failures worth naming into one sentence.
// Everything else is left to the raw log lines the caller appends: a wrong guess about
// what a line means is worse than showing the line.
func pptpOutLogTell(log string) string {
	if log == "" {
		return ""
	}
	tail := pppOutLastLines(log, 80)
	switch {
	case strings.Contains(tail, "MPPE required but peer negotiation failed"),
		strings.Contains(tail, "MPPE required, but MS-CHAP[v2] auth not performed"):
		return "the server would not encrypt the link (MPPE), which this tunnel requires; " +
			"check that the account is allowed MS-CHAPv2, or set mppe to off to accept a cleartext tunnel"
	case strings.Contains(tail, "MPPE required but kernel has no support"):
		return "the kernel has no MPPE support (the ppp_mppe module is missing), so an encrypted PPTP tunnel cannot be built here"
	case strings.Contains(tail, "authentication failed"), strings.Contains(tail, "Authentication failed"),
		strings.Contains(tail, "MS-CHAP authentication failed"), strings.Contains(tail, "CHAP authentication failed"):
		return "the server rejected the username or password"
	case strings.Contains(tail, "Connection refused"), strings.Contains(tail, "Couldn't connect to"):
		return "nothing answered on TCP 1723 at that address (wrong host, or the control port is blocked)"
	case strings.Contains(tail, "No route to host"), strings.Contains(tail, "Network is unreachable"):
		return "the server address is not reachable from this host"
	case strings.Contains(tail, "Timeout"), strings.Contains(tail, "timed out"):
		return "the server did not answer in time; PPTP also needs IP protocol 47 (GRE) to reach it, " +
			"which many networks and every carrier-grade NAT drop"
	case strings.Contains(tail, "LCP: timeout sending Config-Requests"):
		return "the control channel connected but no PPP frames came back, which is what a firewall " +
			"or NAT dropping GRE (IP protocol 47) looks like"
	case strings.Contains(tail, "Modem hangup"):
		return "the server closed the call"
	}
	return ""
}

// ---------------------------------------------------------------------------
// the shared pppd layer (also used by vpnout_sstp.go)
// ---------------------------------------------------------------------------

// pppOutResolveIface returns the ppp device carrying THIS tunnel's session, or "".
//
// Naming the wrong device is the worst thing either pppd driver can do. The
// synthesized freedom outbound binds SO_BINDTODEVICE to whatever comes back here, so a
// wrong answer sends this outbound's traffic through an unrelated tunnel, or through
// an INBOUND client's link where it is billed to their account, and everything looks
// healthy from the panel. The device index is chosen by the kernel and is not knowable
// in advance, so the answer is PROVEN rather than guessed, in three steps:
//
//  1. pppd is given `ifname`, so the name it renames its unit to is ours. On its own
//     that is not proof of anything: the rename is best effort (pppd logs "Couldn't
//     rename interface" and carries on with pppN), and a device of that name could be
//     left over from a pppd that has since died.
//  2. pppd writes <rundir>/ppp-<linkname>.pid for the link named by `linkname`: its own
//     pid on the first line and, once the unit exists, the interface name on the
//     second. That file was written by OUR link's pppd and nobody else's.
//  3. pppd ALSO writes <rundir>/<ifname>.pid holding the pid of the pppd that owns that
//     device. Matching it against the pid from step 2 is what turns "a name in a file"
//     into proof, and because it can be searched across every ppp device on the box it
//     also covers the case where the rename failed or the second line is not there
//     yet.
//
// The pid is checked for liveness first, so a stale file naming an index the kernel has
// since handed to an inbound client's session cannot be claimed. "Watch for a new ppp
// device that appeared after we dialled" was the alternative and is rejected on exactly
// that point: it is a guess, and it guesses wrong precisely when the box is busy, which
// is when being wrong costs the most.
//
// A device counts only once it carries an IPv4 address, i.e. once IPCP has finished:
// binding a socket to an addressless device gives it no source address, the kernel
// then picks one belonging to another interface, and the peer drops the packets.
func pppOutResolveIface(linkname, want, proc string) string {
	if pid, recorded := pppOutLinkPid(linkname); pid > 0 && pppOutProcessAlive(pid) {
		if recorded != "" && pppOutDevPid(recorded) == pid && pppOutIfaceReady(recorded) {
			return recorded
		}
		if owned := pppOutIfaceOwnedBy(pid); owned != "" && pppOutIfaceReady(owned) {
			return owned
		}
	}
	// No usable pid file, which is what a pppd with a runtime directory we do not know
	// about looks like. Fall back to the device we named ourselves, and only while our
	// own supervised pppd is alive: nothing else on this box creates that name, and
	// pppd deletes its device when it exits, so a device with our name under a running
	// instance of ours is ours.
	if want != "" && pppOutIfaceReady(want) && procMgr.IsRunning(proc) {
		return want
	}
	return ""
}

// pppOutRunDirs lists where a pppd might keep its pid files. The bundled pppd (2.5.x)
// uses /run/ppp, which is where these were verified; distro builds of 2.4.x use
// /var/run or /var/run/pppd. On most hosts /var/run is a symlink to /run, so the
// duplicates cost one failed stat each.
var pppOutRunDirs = []string{"/run/ppp", "/var/run/ppp", "/run/pppd", "/var/run/pppd", "/run", "/var/run"}

// pppOutLinkPid reads <rundir>/ppp-<linkname>.pid: pppd's pid, and the interface name
// once that pppd has created its unit.
func pppOutLinkPid(linkname string) (int, string) {
	for _, dir := range pppOutRunDirs {
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

// pppOutDevPid reads <rundir>/<iface>.pid: the pid of the pppd owning that device.
func pppOutDevPid(iface string) int {
	for _, dir := range pppOutRunDirs {
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

// pppOutIfaceOwnedBy finds the device whose pppd has the given pid.
//
// Every device on the box is a candidate and the answer comes only from pid files:
// nothing is inferred from a name. Filtering by name first was the obvious shortcut and
// is wrong twice over. It assumes the rename succeeded, which is the one case this
// function exists to cover (pppd logs "Couldn't rename interface" and carries on with
// pppN), and it would claim a device on the strength of its name, which is exactly what
// a leftover from a previous panel has. A device whose <rundir>/<dev>.pid holds a pid we
// have already proved to be our own pppd is ours whatever it happens to be called, and
// a device with no such file cannot be. The cost is one failed stat per unrelated
// interface, on a fallback path.
func pppOutIfaceOwnedBy(pid int) string {
	links, err := netlink.LinkList()
	if err != nil {
		return ""
	}
	for _, l := range links {
		if dev := l.Attrs().Name; pppOutDevPid(dev) == pid {
			return dev
		}
	}
	return ""
}

// pppOutProcessAlive reports whether the pid exists. EPERM counts as alive: the process
// is there and owned by somebody else, which is still "not free to be reused".
func pppOutProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// pppOutIfaceReady reports whether the device exists and has finished IPCP.
func pppOutIfaceReady(iface string) bool { return pppOutIfaceAddr(iface) != "" }

// pppOutIfaceAddr returns the device's first IPv4 address, or "".
func pppOutIfaceAddr(iface string) string {
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

// pppOutResolveV4 turns a configured server into a single IPv4 address. `what` names
// the field in the error, because "cannot resolve" on its own does not tell an
// operator which of the addresses they typed is the broken one.
func pppOutResolveV4(server, what string) (net.IP, error) {
	if ip := net.ParseIP(server); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("the %s address %q is IPv6, and this client is IPv4 only", what, server)
	}
	ips, err := net.LookupIP(server)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve the %s %q: %w", what, server, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("the %s %q has no IPv4 address", what, server)
}

// pppOutSafeName reduces a tag to something usable as a filename, a procmgr key and
// part of a device name. Tags are operator input and only spaces are refused upstream.
func pppOutSafeName(tag string) string {
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

func pppOutHash(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// pppOutQuote renders a value for pppd's options parser, which understands
// double-quoted strings with backslash escapes.
func pppOutQuote(v string) string {
	esc := strings.ReplaceAll(v, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	return `"` + esc + `"`
}

// pppOutShellQuote renders a value for /bin/sh, which is what parses pppd's `pty`
// argument and openconnect's `--script`.
func pppOutShellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// pppOutFingerprintOf hashes the operator's settings so a later Up can tell "already
// running" from "already running with something other than what was just typed".
func pppOutFingerprintOf(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%08x", pppOutHash(string(b)))
}

// pppOutStoredFingerprint reads back the fingerprint of a generated file, or "".
func pppOutStoredFingerprint(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(ln, pppOutFingerprintMark) {
			return strings.TrimSpace(strings.TrimPrefix(ln, pppOutFingerprintMark))
		}
	}
	return ""
}

// pppOutBytes renders a device counter.
func pppOutBytes(n uint64) string {
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

// pppOutLastLines returns the final n lines of a log.
func pppOutLastLines(log string, n int) string {
	if log == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func pppOutLogLines(log string) int {
	if log == "" {
		return 0
	}
	return len(strings.Split(strings.TrimRight(log, "\n"), "\n"))
}

// pppOutLogSince returns the log from the given line onwards, i.e. the current
// attempt's output only.
//
// The offset drifts if the ring buffer discarded lines in between (it holds 800), but
// it drifts in the safe direction: a discard makes this skip PAST some new lines, so at
// worst a tell is missed and the wait ends on its timeout, which still shows the tail.
// The opposite mistake, reading an older attempt's failure as this one's, is the one
// that matters and cannot happen.
func pppOutLogSince(log string, mark int) string {
	if log == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if mark >= len(lines) {
		return ""
	}
	if mark > 0 {
		lines = lines[mark:]
	}
	return strings.Join(lines, "\n")
}
