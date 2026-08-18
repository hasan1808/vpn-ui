package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/vishvananda/netlink"

	"github.com/hasan1808/pro-ui/backend"
)

// SSTP as an OUTBOUND: the panel dials somebody else's SSTP server (Windows RRAS, an
// accel-ppp box, another vpn-ui) over TLS on 443 and Xray egresses through the ppp
// device that comes up.
//
// The server side (sstp.go) is accel-ppp, which has no client mode at all, so this
// drives a different project: sstp-client. Same inverted process tree as the PPTP twin,
// and for a much harder reason:
//
//	pppd  pty "<sstpc> --nolaunchpppd --ipparam <id> <server>"  file <options>
//	  \_ sstpc                                                  <- TLS + SSTP framing
//
// sstpc CAN launch pppd itself, and that mode is the one this driver must not use. It
// execs a hard-coded /usr/sbin/pppd, and the pppd that ends up there is whatever the
// distro installed. That matters because of the plugin:
//
// sstp-pppd-plugin.so is what makes an SSTP call survive. SSTP demands a "crypto
// binding": proof that whoever just authenticated over PPP also owns the TLS channel,
// computed from the MPPE master keys that only pppd ever sees. pppd hands them out
// through this plugin over a unix socket back to sstpc. Without it the login succeeds
// and the server then drops the call, naming nothing. And the plugin is MUSL-linked
// (readelf: NEEDED libc.musl-x86_64.so.1), so only the bundled musl pppd can dlopen
// it: a glibc host with distro ppp installed would load nothing and produce exactly
// that unattributable drop.
//
// So this driver invokes backend.PppdBundled by ABSOLUTE PATH and never asks
// backend.UsingBundledPppd(), which defers to a host pppd whenever one exists. The
// plugin is likewise loaded by absolute path, which pppd supports directly: a `plugin`
// argument containing a slash is dlopen'd as given rather than resolved against pppd's
// compiled-in plugin directory.
//
// The pppd layer (interface discovery, options quoting, log slicing) is shared with
// vpnout_pptp.go, where the pppOut* helpers live.
const (
	// sstpOutIfPrefix names the client's ppp devices, clear of the PPTP client's
	// pptpo- and of the L2TP client's l2o-. The SSTP SERVER never creates a device of
	// this shape either: accel-ppp's sessions are plain pppN.
	sstpOutIfPrefix = "sstpo-"

	// sstpOutRunDir is sstp-client's compiled-in runtime directory
	// (--with-runtime-dir=/var/run/sstpc in build/backend/sstpc-bundle.sh). It is where
	// sstpc binds the unix socket the pppd plugin connects back to.
	sstpOutRunDir = "/var/run/sstpc"

	// sstpOutConfDir holds this driver's generated files (a CA certificate, when the
	// operator supplies one). Deliberately NOT under /etc/vpn-ui-sstp, which the SSTP
	// SERVER regenerates per inbound.
	sstpOutConfDir = "/etc/vpn-ui-sstp-out"

	// sstpOutDialTimeout bounds the wait for the link. Longer than the PPTP twin's
	// because there is a full TLS handshake, an HTTP layer and the SSTP call setup in
	// front of the PPP negotiation. It is a panel-boot cost too, because
	// InitVpnOutbound raises tunnels one at a time before Xray starts.
	sstpOutDialTimeout = 45 * time.Second
)

// sstpOutSettings is the SSTP slice of one outbound tunnel's opaque Settings blob.
type sstpOutSettings struct {
	// Server is what sstp-client is handed verbatim: a hostname, host:port, or a full
	// https:// URL. SSTP is TLS on 443 by default, which is most of the point of the
	// protocol (it survives networks that drop everything else).
	Server   string `json:"server"`
	Username string `json:"username"` // PPP username
	Password string `json:"password"` // PPP password

	// AuthProto pins which protocol we prove OURSELVES with: "" / "mschapv2" (the
	// default, and the only one that produces MPPE keys on every server), "mschap",
	// "chap", "pap" or "auto".
	AuthProto string `json:"authProto"`

	// CaCert is the PEM that signed the server's certificate, for the very common case
	// of a self-signed SSTP gateway (this panel's own SSTP core self-signs by default).
	CaCert string `json:"caCert"`

	// AllowInsecureCert turns certificate failures into warnings (sstpc --cert-warn).
	// It is the escape hatch for a gateway whose certificate cannot be verified at all,
	// and it gives up the only thing authenticating the server.
	AllowInsecureCert bool `json:"allowInsecureCert"`

	// Proxy dials the SSTP server THROUGH a proxy rather than straight out of the
	// host's WAN, wrapping the OUTER TLS connection. It is the only mechanism that
	// exists for it: sockopt.dialerProxy is on the wrong side of the tunnel and the
	// synthesis deletes it (see vpnOutStreamSettings).
	//
	// HTTP CONNECT ONLY, and this is the trap. The field takes a URL, so the obvious
	// thing to do with it is point it at a SOCKS listener, and sstp-client does not
	// refuse that - it does not look at the scheme AT ALL. Measured against the
	// bundled sstp-client 1.0.20 with `socks5://127.0.0.1:<port>`: it opened a plain
	// TCP connection and sent `CONNECT vpn.invalid:443 HTTP/1.1` to it. A SOCKS server
	// receiving that answers with a protocol error or nothing, and the operator is
	// left with "Could not connect to proxy server" against a proxy that is up and
	// working. The binary confirms the same thing: it carries `CONNECT %s:443
	// HTTP/1.1` and `Proxy-Authorization: %s` and not one SOCKS string. So Validate
	// refuses a non-HTTP scheme rather than letting the dial discover it.
	//
	// Credentials go in the URL's userinfo (http://user:pass@host:port), which is the
	// only way sstpc takes them: with none, a proxy that challenges gets "Proxy asked
	// for credentials, none provided". They are passed on the pty command line, which
	// is a difference from the OpenConnect driver worth knowing about - see ptyCommand.
	Proxy string `json:"proxy"`

	Mtu int `json:"mtu"`
}

type sstpOutDriver struct{}

var _ VpnOutSecrets = (*sstpOutDriver)(nil)

func init() { RegisterVpnOutDriver(VpnOutSSTP, &sstpOutDriver{}) }

// SecretKeys keeps the PPP password off the wire to the browser. Same omission and the
// same shape as the PPTP driver's: the settings blob was served to /vpnoutbound/list
// as stored, password included, behind a form field that renders blank.
//
// caCert is deliberately NOT here. It is the certificate the gateway presents, which is
// public by construction and the first thing to check when a TLS handshake is refused.
func (d *sstpOutDriver) SecretKeys() []string { return []string{"password"} }

func (d *sstpOutDriver) parse(cfg VpnOutboundConfig) (*sstpOutSettings, error) {
	s := &sstpOutSettings{}
	if len(cfg.Settings) > 0 {
		if err := json.Unmarshal(cfg.Settings, s); err != nil {
			return nil, fmt.Errorf("sstp outbound %q: unreadable settings: %w", cfg.Tag, err)
		}
	}
	s.Server = strings.TrimSpace(s.Server)
	s.Username = strings.TrimSpace(s.Username)
	s.AuthProto = strings.ToLower(strings.TrimSpace(s.AuthProto))
	s.Proxy = strings.TrimSpace(s.Proxy)
	return s, nil
}

// ServerHost names what the outer TLS goes to, so this tunnel can be carried inside
// another. The proxy wins when there is one: with `--proxy` set, sstpc connects to the
// proxy and never to the gateway, so a rule naming the gateway would match nothing.
func (d *sstpOutDriver) ServerHost(cfg VpnOutboundConfig) (string, error) {
	s, err := d.parse(cfg)
	if err != nil {
		return "", err
	}
	if s.Proxy != "" {
		return s.Proxy, nil
	}
	return s.Server, nil
}

// Available reports whether an SSTP outbound can run here at all.
//
// backend.ClientAvailable already folds in the plugin, and names it as the plugin
// rather than as a generic sstpc failure, because a missing companion is invisible at
// raise time and the consequence is the useful half of the message.
//
// The bundled pppd is checked on top of that, and as a HARD requirement rather than
// the soft one the PPTP twin makes of it: this protocol has no path that works with a
// distro pppd, so on an architecture with no pppd bundle there is nothing to fall back
// to. Refused here at save time rather than discovered later as a call that keeps
// being dropped after a successful login.
//
// Both halves say the same thing about the fix, because both are bundle contents:
// neither a distribution package nor a core install can supply either one. The SSTP
// core installs accel-ppp, which is the SERVER. So the message names the only real fix
// rather than sending the operator to Core Settings for something that is not there.
func (d *sstpOutDriver) Available() (bool, string) {
	if ok, why := backend.ClientAvailable(backend.SstpClient); !ok {
		return false, why + ". No package or core supplies it: the driver runs the bundled client only, " +
			"so this needs a vpn-ui build for " + runtime.GOARCH
	}
	if !backend.HasPppdBundle() {
		return false, "SSTP needs the bundled pppd, which this build does not carry for " + runtime.GOARCH + ": " +
			"the sstp pppd plugin is musl-linked, so installing your distribution's ppp cannot stand in " +
			"(it could not load the plugin, and the server would drop the call right after a successful login). " +
			"This needs a vpn-ui build for this architecture"
	}
	return true, ""
}

// Validate refuses a config while the modal is still open.
func (d *sstpOutDriver) Validate(cfg VpnOutboundConfig) error {
	s, err := d.parse(cfg)
	if err != nil {
		return err
	}
	if s.Server == "" {
		return errors.New("the SSTP server address is required")
	}
	if s.Username == "" {
		return errors.New("a PPP username is required")
	}
	if s.Password == "" {
		return errors.New("a PPP password is required")
	}
	if strings.ContainsAny(s.Username+s.Password, "\r\n") {
		return errors.New("the username and password cannot contain line breaks")
	}
	// The server ends up inside pppd's `pty` string, which /bin/sh parses. It is
	// single-quoted on the way in, so a quote is the one character that could still
	// change the shape of that command line.
	if strings.ContainsAny(s.Server, "\r\n'") || strings.ContainsAny(s.Proxy, "\r\n'") {
		return errors.New("the server address and proxy URL cannot contain quotes or line breaks")
	}
	if err := sstpOutValidateProxy(s.Proxy); err != nil {
		return err
	}
	switch s.AuthProto {
	case "", "auto", "mschapv2", "mschap", "chap", "pap":
	default:
		return fmt.Errorf("unknown authentication protocol %q", s.AuthProto)
	}
	// PAP and CHAP produce no MPPE keys, and with no MPPE keys there is no crypto
	// binding for sstpc to answer with. The server accepts the login and then hangs up,
	// which is the single hardest failure in this protocol to read from a log, so it is
	// refused here where it can be explained.
	if s.AuthProto == "pap" || s.AuthProto == "chap" {
		return fmt.Errorf("SSTP cannot use %s: the crypto binding the server checks after login is "+
			"computed from the MPPE keys, and only MS-CHAP produces them. Use mschapv2",
			strings.ToUpper(s.AuthProto))
	}
	if strings.TrimSpace(s.CaCert) != "" && !strings.Contains(s.CaCert, "-----BEGIN") {
		return errors.New("the CA certificate does not look like PEM (no -----BEGIN----- line)")
	}
	if s.Mtu != 0 && (s.Mtu < 576 || s.Mtu > 1500) {
		return fmt.Errorf("mtu %d is outside 576..1500", s.Mtu)
	}
	return nil
}

// Up dials the server and returns the ppp device Xray should bind egress to.
func (d *sstpOutDriver) Up(cfg VpnOutboundConfig) (string, error) {
	s, err := d.parse(cfg)
	if err != nil {
		return "", err
	}
	if err := d.Validate(cfg); err != nil {
		return "", err
	}
	name := pppOutSafeName(cfg.Tag)
	iface := sstpOutIfName(cfg.Tag)
	proc := sstpOutProcName(name)
	opts := sstpOutOptsFile(name)

	// Idempotence, keyed on a fingerprint of the settings rather than on the tunnel
	// merely being alive: returning early on a live-but-stale tunnel would report a
	// changed password as saved while pppd kept using the old one. The LIVE device is
	// returned, because pppd's rename is best effort and a redial moves the index.
	if procMgr.IsRunning(proc) && pppOutStoredFingerprint(opts) == pppOutFingerprintOf(s) {
		if got := pppOutResolveIface(sstpOutLinkName(name), iface, proc); got != "" {
			return got, nil
		}
	}

	// Nothing else in the panel lays the client binaries down: no core owns them, so
	// without this they stay embedded and never reach disk.
	if err := backend.EnsureClients(); err != nil {
		return "", fmt.Errorf("could not unpack the bundled VPN clients: %w", err)
	}
	sstpc := backend.ClientPath(backend.SstpClient)
	if sstpc == "" {
		return "", errors.New("the sstpc client is not on disk and is not bundled for this architecture")
	}
	plugin := backend.SstpPluginPath()
	if plugin == "" {
		return "", errors.New("sstp-pppd-plugin.so is missing, so the SSTP crypto binding cannot be answered " +
			"and the server would drop the call right after login")
	}
	pppd, err := sstpOutPppd()
	if err != nil {
		return "", err
	}

	// Reap daemons orphaned by a panel that died without a clean shutdown, before our
	// own child exists: it pkills by binary path, and letting it fire later would shoot
	// a live session down.
	migrateFromSystemd()
	for _, mod := range []string{"ppp_generic", "ppp_async", "ppp_mppe"} {
		_ = exec.Command("modprobe", mod).Run()
	}

	if err := os.MkdirAll(sstpOutRunDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create %s, which sstpc needs for its plugin socket: %w", sstpOutRunDir, err)
	}
	// A socket left behind by an sstpc that was killed rather than stopped would fail
	// the bind, and the failure reads as a connection problem. Safe to remove
	// unconditionally here: this path is derived from the tag, nothing else uses it,
	// and we only reach this point when we are about to (re)start our own instance.
	_ = os.Remove(sstpOutSockPath(name))

	caFile := ""
	if strings.TrimSpace(s.CaCert) != "" {
		if caFile, err = d.writeCaFile(name, s.CaCert); err != nil {
			return "", err
		}
	}
	if err := d.writeOptions(name, iface, plugin, s); err != nil {
		return "", err
	}

	// Where THIS attempt's output starts, so a stale failure from the run that made the
	// operator fix their password cannot fail the save that fixed it.
	logMark := pppOutLogLines(procMgr.Logs(proc))

	args := []string{
		"file", opts,
		"pty", d.ptyCommand(sstpc, name, caFile, s),
		// Foreground, or procmgr supervises a process that forks away immediately and
		// restarts it every five seconds forever.
		"nodetach",
		"ifname", iface,
		"linkname", sstpOutLinkName(name),
		"ipparam", sstpOutLinkName(name),
	}
	// No environment: backend.PppdBundled is a launcher script that exports
	// OPENSSL_MODULES for the bundle's own OpenSSL legacy provider itself (MS-CHAP and
	// MPPE need it), and pppdEnv() would answer nil here anyway, because it asks
	// UsingBundledPppd() and this driver deliberately does not.
	if err := procMgr.Start(proc, pppd, args, nil, ""); err != nil {
		return "", fmt.Errorf("start the sstp client for %q: %w", cfg.Tag, err)
	}

	got, err := d.waitForIface(name, iface, proc, logMark)
	if err != nil {
		// Save does not persist a config whose Up failed, so a dialling pppd left behind
		// here would be a process nothing has a record of and nothing will ever stop.
		_ = d.Down(cfg)
		return "", err
	}
	return got, nil
}

// Down stops the client and removes what it wrote.
func (d *sstpOutDriver) Down(cfg VpnOutboundConfig) error {
	name := pppOutSafeName(cfg.Tag)
	// The group signal is what takes sstpc with it: it is pppd's pty child and shares
	// its process group. pppd removes its own device and pid files on the way out.
	_ = procMgr.Stop(sstpOutProcName(name))
	_ = os.Remove(sstpOutOptsFile(name))
	// The socket is sstpc's, and an sstpc that was killed rather than asked to stop
	// leaves it behind to fail the next bind.
	_ = os.Remove(sstpOutSockPath(name))
	// Holds the operator's CA certificate, which is public, but Up rewrites every byte
	// of the directory so there is nothing to preserve.
	_ = os.RemoveAll(sstpOutDir(name))
	return nil
}

// Status reports the supervised client and the kernel device separately, because they
// come apart: a pppd that is retrying is alive and has no device, and a pppd whose
// server vanished can hold a device that carries nothing.
func (d *sstpOutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	name := pppOutSafeName(cfg.Tag)
	proc := sstpOutProcName(name)
	running := procMgr.IsRunning(proc)
	iface := pppOutResolveIface(sstpOutLinkName(name), sstpOutIfName(cfg.Tag), proc)

	logs := procMgr.Logs(proc)
	if iface == "" {
		if tell := sstpOutLogTell(logs); tell != "" {
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
		parts = append(parts, "CLIENT STOPPED")
	}
	return running, strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// naming and paths
// ---------------------------------------------------------------------------

// sstpOutIfName maps a tag to a bounded, deterministic device name: deterministic
// because Down and Status get nothing but the stored config, bounded because the
// kernel refuses anything past IFNAMSIZ-1 and pppd then silently keeps pppN.
func sstpOutIfName(tag string) string {
	safe := pppOutSafeName(tag)
	if len(safe) <= pppOutIfMax-len(sstpOutIfPrefix) {
		return sstpOutIfPrefix + safe
	}
	return fmt.Sprintf("%s%08x", strings.TrimSuffix(sstpOutIfPrefix, "-"), pppOutHash(tag))
}

// sstpOutProcName is the procmgr key, clear of the server side's "sstp-server-<id>".
func sstpOutProcName(name string) string { return "sstp-out-" + name }

// sstpOutLinkName is pppd's `linkname` and sstpc's `--ipparam`, deliberately the same
// string: it names the per-link pid file that proves which device is ours, and it is
// also what sstpc builds its socket path from.
func sstpOutLinkName(name string) string { return "sstp-out-" + name }

// sstpOutSockPath is the unix socket sstpc binds and the pppd plugin connects back to.
//
// This path is not a convention, it is a calculation sstp-client performs and cannot
// be told: sstp-event.c builds it as
//
//	snprintf(..., "%s/sstpc-%s", SSTP_RUNTIME_DIR, opts->ipparam ? opts->ipparam : "uds-sock")
//
// with SSTP_RUNTIME_DIR fixed at build time (/var/run/sstpc here). The two sides find
// each other only if this matches exactly, so --ipparam is passed to sstpc and the same
// value is spelled into the pppd plugin's `sstp-sock` option below.
func sstpOutSockPath(name string) string {
	return sstpOutRunDir + "/sstpc-" + sstpOutLinkName(name)
}

func sstpOutDir(name string) string      { return sstpOutConfDir + "/" + name }
func sstpOutCaFile(name string) string   { return sstpOutDir(name) + "/ca.pem" }
func sstpOutOptsFile(name string) string { return "/etc/ppp/options.sstp-out-" + name }

// sstpOutPppd resolves the ONE pppd that can run this protocol.
//
// No fallback to a host pppd, unlike every other pppd user in this package. See the
// file header: the plugin is musl-linked, a glibc pppd cannot dlopen it, and the
// resulting failure (a call dropped after a successful login) names nothing at all.
// Failing here with a sentence is strictly better than that.
func sstpOutPppd() (string, error) {
	if !backend.HasPppdBundle() {
		return "", errors.New("SSTP needs the bundled pppd, which is not included for this architecture")
	}
	if _, err := os.Stat(backend.PppdBundled); err != nil {
		if err := backend.ExtractPppdBundle(); err != nil {
			return "", fmt.Errorf("could not unpack the bundled pppd: %w", err)
		}
	}
	if _, err := os.Stat(backend.PppdBundled); err != nil {
		return "", fmt.Errorf("the bundled pppd is not at %s: %w", backend.PppdBundled, err)
	}
	return backend.PppdBundled, nil
}

// ---------------------------------------------------------------------------
// the two command lines
// ---------------------------------------------------------------------------

// ptyCommand builds the string pppd runs behind the pseudo-terminal. /bin/sh parses
// it, so every value is single-quoted.
//
// It carries NO credentials, which is the point of running pppd as the parent: sstpc's
// --user and --password exist only to pass through to a pppd it launches itself, and
// in this mode the PPP authentication is pppd's, out of a 0600 options file. So
// nothing here is visible in `ps`.
func (d *sstpOutDriver) ptyCommand(sstpc, name, caFile string, s *sstpOutSettings) string {
	parts := []string{
		pppOutShellQuote(sstpc),
		// pppd is the parent, so sstpc must not start one of its own: that mode execs a
		// hard-coded /usr/sbin/pppd, which is the distro's and cannot load the plugin.
		"--nolaunchpppd",
		// Names the plugin socket (see sstpOutSockPath) and tags sstpc's syslog lines.
		"--ipparam", pppOutShellQuote(sstpOutLinkName(name)),
		// sstpc logs to syslog by default, where the panel cannot show it. Its stderr is
		// safe to use: with `logfd 1` pppd points the pty child's stderr at its own
		// stdout, not at the pseudo-terminal, so these lines land in the procmgr ring
		// buffer instead of being injected into the PPP stream.
		"--log-stderr",
	}
	if caFile != "" {
		parts = append(parts, "--ca-cert", pppOutShellQuote(caFile))
	} else if bundle := ocOutCABundle(); bundle != "" {
		// The same trust-store problem the OpenConnect driver documents at length, and
		// the reason that probe is shared rather than copied: this is another statically
		// linked client carrying ONE compiled-in default CA location, chosen on Alpine,
		// and it is simply absent on a RHEL-family host. Naming the host's real bundle
		// turns "every certificate is untrusted here" back into ordinary verification.
		parts = append(parts, "--ca-cert", pppOutShellQuote(bundle))
	}
	if s.AllowInsecureCert {
		parts = append(parts, "--cert-warn")
	}
	if s.Proxy != "" {
		parts = append(parts, "--proxy", pppOutShellQuote(s.Proxy))
	}
	// SNI, but only for a name. Sending an IP literal in a TLS server-name extension is
	// not allowed and gateways behind a reverse proxy answer it with the wrong
	// certificate or a handshake failure, so an address that is already an IP is left
	// without one.
	if net.ParseIP(sstpOutHostOf(s.Server)) == nil {
		parts = append(parts, "--tls-ext")
	}
	// The server goes last: sstpc's usage is `sstpc <options> <hostname>`.
	parts = append(parts, pppOutShellQuote(s.Server))
	return strings.Join(parts, " ")
}

// sstpOutValidateProxy refuses a proxy URL this client cannot actually use.
//
// It exists for exactly one mistake, and it is the one an operator makes first: the box
// takes a URL, so they point it at the SOCKS listener they already run. sstp-client does
// not refuse that, because it never looks at the scheme. Measured against the bundled
// 1.0.20 with `socks5://127.0.0.1:<port>`: it opened a plain TCP connection to that
// address and wrote `CONNECT vpn.invalid:443 HTTP/1.1` into it. What comes back from a
// SOCKS server handed an HTTP request is a protocol error or silence, and sstpc reports
// "Could not connect to proxy server" about a proxy that is running perfectly. Nothing
// downstream can tell that apart from a dead proxy, so it is refused here instead.
//
// https is accepted alongside http and means only "the proxy is on 443": measured the
// same way, sstpc sends the identical CLEARTEXT CONNECT to it. Refusing it would break
// a tunnel that works today for a scheme that changes nothing.
//
// A URL with no scheme at all is also accepted. sstpc's parser leaves the scheme unset
// and falls back to port 80, which is a working HTTP proxy configuration and may
// already be stored on a live tunnel.
func sstpOutValidateProxy(raw string) error {
	p := strings.TrimSpace(raw)
	i := strings.Index(p, "://")
	if p == "" || i < 0 {
		return nil
	}
	switch scheme := strings.ToLower(p[:i]); scheme {
	case "http", "https":
		return nil
	case "socks", "socks4", "socks4a", "socks5", "socks5h":
		return fmt.Errorf("the SSTP client speaks HTTP CONNECT proxies only, so a %s:// proxy "+
			"cannot work here: it would send an HTTP request to the SOCKS port and then report "+
			"the proxy as unreachable. Give an HTTP proxy, or use an OpenConnect or OpenVPN "+
			"outbound, whose clients do speak SOCKS5", scheme)
	default:
		return fmt.Errorf("proxy scheme %q is not one the SSTP client understands; it speaks "+
			"HTTP CONNECT proxies only", scheme)
	}
}

// sstpOutHostOf strips a scheme, a port and a path off the configured server so the
// remainder can be tested for being an IP literal.
func sstpOutHostOf(server string) string {
	h := server
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	if strings.HasPrefix(h, "[") { // bracketed IPv6 literal
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i+1:], ":") {
		h = h[:i]
	}
	return h
}

// writeCaFile lays the operator's CA PEM down for sstpc to verify the server against.
func (d *sstpOutDriver) writeCaFile(name, pem string) (string, error) {
	if err := os.MkdirAll(sstpOutDir(name), 0700); err != nil {
		return "", err
	}
	body := strings.TrimSpace(pem) + "\n"
	if err := os.WriteFile(sstpOutCaFile(name), []byte(body), 0644); err != nil {
		return "", err
	}
	return sstpOutCaFile(name), nil
}

// writeOptions renders the pppd options file.
//
// Three things in here are load-bearing and none of them is obvious from the outside:
//
//   - plugin <absolute path>. pppd dlopen's a `plugin` argument containing a slash
//     directly instead of resolving it against its compiled-in plugin directory, which
//     is what lets the panel load a plugin that lives beside its own binary. The
//     `sstp-sock` option below only exists once that plugin is loaded, so the order of
//     these two lines is not cosmetic.
//
//   - NO require-mppe-128, and that is deliberate. The crypto binding the server checks
//     after login is computed from the MPPE MASTER keys, but those are a by-product of
//     the MS-CHAPv2 exchange itself and exist whether or not CCP ever negotiates
//     encryption on the link: pppd prints them ("The mppe send key") right after
//     "CHAP authentication succeeded", and the plugin hands them to sstpc from there.
//     Requiring MPPE conflates the two and breaks the dial against a server that
//     correctly declines to encrypt an already-TLS-wrapped link, which includes this
//     panel's OWN SSTP inbound (accel-ppp, mppe=deny, for exactly that reason). Measured
//     against it: with require-mppe-128 the server answers CCP with every algorithm bit
//     clear, pppd gives up with "MPPE required but peer negotiation failed" and tears
//     the call down a moment after a SUCCESSFUL login; without it the same session
//     derives the same keys, completes IPCP and carries traffic. Nothing is weakened -
//     SSTP is PPP inside TLS, and MPPE is still negotiated whenever the server asks.
//     PAP and CHAP produce no keys at all, which is why Validate refuses them.
//
//   - nodefaultroute, and never usepeerdns. An SSTP server hands out a default route,
//     and pppd installs one by default (a distro /etc/ppp/options carrying
//     `defaultroute` is read before this file, so silence is not refusal). Taking it
//     would move the whole HOST into somebody else's tunnel, including the TLS
//     connection carrying this very tunnel, which then loops. Egress here is opt-in per
//     Xray outbound: SO_BINDTODEVICE plus the private table the framework installs.
func (d *sstpOutDriver) writeOptions(name, iface, plugin string, s *sstpOutSettings) error {
	mtu := s.Mtu
	if mtu == 0 {
		// PPP inside SSTP inside TLS inside TCP. 1400 is the value the panel's own SSTP
		// server uses and leaves room for all of it.
		mtu = 1400
	}

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui (SSTP client outbound) - do not edit\n")
	b.WriteString(pppOutFingerprintMark + pppOutFingerprintOf(s) + "\n")
	b.WriteString(fmt.Sprintf("plugin %s\n", plugin))
	b.WriteString(fmt.Sprintf("sstp-sock %s\n", sstpOutSockPath(name)))

	// We are the client: the server does not authenticate itself to us over PPP (it
	// authenticated with its TLS certificate).
	b.WriteString("noauth\n")
	b.WriteString("refuse-eap\n")
	switch s.AuthProto {
	case "mschap":
		b.WriteString("refuse-pap\nrefuse-chap\nrefuse-mschap-v2\n")
	case "auto":
		// Anything but EAP. Every SSTP server in practice picks MS-CHAPv2.
	default: // "" and "mschapv2"; pap and chap are refused by Validate
		b.WriteString("refuse-pap\nrefuse-chap\nrefuse-mschap\n")
	}
	// MPPE is negotiated if the server asks for it and skipped if it does not; see the
	// header for why requiring it breaks the handshake it was meant to protect.
	// It is a stream cipher over the PPP payload and cannot be combined with stateful
	// compression: pppd would negotiate both and then drop every frame.
	b.WriteString("nobsdcomp\nnodeflate\nnovj\nnovjccomp\n")

	b.WriteString(fmt.Sprintf("name %s\n", pppOutQuote(s.Username)))
	b.WriteString(fmt.Sprintf("password %s\n", pppOutQuote(s.Password)))
	// remotename, because pppd matches a secrets-file entry on the pair (client,
	// server) and an SSTP peer sends no name of its own. With `password` given inline
	// nothing is looked up, but a stale /etc/ppp/chap-secrets on the host stays out of
	// the decision either way.
	b.WriteString(fmt.Sprintf("remotename %s\n", sstpOutLinkName(name)))

	b.WriteString(fmt.Sprintf("ifname %s\n", iface))
	b.WriteString(fmt.Sprintf("linkname %s\n", sstpOutLinkName(name)))
	b.WriteString(fmt.Sprintf("ipparam %s\n", sstpOutLinkName(name)))
	b.WriteString("noipdefault\nipcp-accept-local\nipcp-accept-remote\n")
	// No IPv6CP: the synthesized outbound binds one device for IPv4 egress, and a
	// negotiated IPv6 address would be a second address family nothing here manages.
	b.WriteString("noipv6\n")
	b.WriteString("nodefaultroute\n")
	// A pty is not a tty, and a distro /etc/ppp/options carrying `lock` would have pppd
	// try to create a UUCP lock file for a device that does not exist.
	b.WriteString("nolock\n")
	b.WriteString(fmt.Sprintf("mtu %d\nmru %d\n", mtu, mtu))
	// SSTP rides TCP, so a dead peer does not announce itself: without echoes the device
	// stays up swallowing everything Xray sends into it.
	b.WriteString("lcp-echo-interval 20\nlcp-echo-failure 3\n")
	// Redial in-process rather than dying and waiting out procmgr's five second window,
	// and never give up: the peer is somebody else's server and a bad afternoon must
	// not need a human to undo.
	b.WriteString("persist\nmaxfail 0\nholdoff 10\n")
	// To stdout, so the panel's log view for this tunnel is not empty. It is also what
	// keeps sstpc's own stderr off the pseudo-terminal: pppd points the pty child's
	// stderr at its log fd, and a log fd of 1 is this process's stdout.
	b.WriteString("logfd 1\n")
	// The pppd here is always the bundled 2.5.x one, so these options certainly exist.
	// They stop the DISTRO's /etc/ppp/ip-up (and its ip-up.d directory) running for this
	// link, which is the other half of keeping the host's resolver and routing table out
	// of the remote's hands: pppd has no way to turn a distro `usepeerdns` back off once
	// /etc/ppp/options has turned it on, but a hook that never runs cannot act on it.
	b.WriteString("ip-up-script /bin/true\nip-down-script /bin/true\n")

	if err := os.MkdirAll("/etc/ppp", 0755); err != nil {
		return err
	}
	// 0600: the file holds the account password.
	return os.WriteFile(sstpOutOptsFile(name), []byte(b.String()), 0600)
}

// ---------------------------------------------------------------------------
// bringing the link up
// ---------------------------------------------------------------------------

// waitForIface blocks until this tunnel's ppp device exists and has finished IPCP,
// reading the log in parallel: the failures that matter (an untrusted certificate, a
// rejected password, a refused crypto binding) never produce a device at all, and
// `persist` means pppd would keep retrying the same one indefinitely.
func (d *sstpOutDriver) waitForIface(name, want, proc string, logMark int) (string, error) {
	deadline := time.Now().Add(sstpOutDialTimeout)
	for {
		if got := pppOutResolveIface(sstpOutLinkName(name), want, proc); got != "" {
			return got, nil
		}
		fresh := pppOutLogSince(procMgr.Logs(proc), logMark)
		if tell := sstpOutLogTell(fresh); tell != "" {
			return "", fmt.Errorf("the sstp client did not connect: %s", tell)
		}
		if !procMgr.IsRunning(proc) {
			return "", fmt.Errorf("the sstp client stopped before the link came up:\n%s",
				pppOutLastLines(fresh, 6))
		}
		if time.Now().After(deadline) {
			last := pppOutLastLines(fresh, 6)
			if last == "" {
				last = "no output from the client"
			}
			return "", fmt.Errorf("the SSTP link did not come up within %s. Last log:\n%s",
				sstpOutDialTimeout, last)
		}
		time.Sleep(pppOutPoll)
	}
}

// sstpOutLogTell turns the failures worth naming into one sentence, and leaves
// everything else to the raw log lines the caller appends.
func sstpOutLogTell(log string) string {
	if log == "" {
		return ""
	}
	tail := pppOutLastLines(log, 80)
	switch {
	// The proxy cases come before everything else because the lines below are broad
	// enough to swallow them: a proxy failure reaches the generic "Connection refused"
	// and "certificate" arms and would be reported as the SERVER's fault, sending the
	// operator to the wrong machine. Each string is one the bundled 1.0.20 prints.
	case strings.Contains(tail, "Could not connect to proxy server"):
		return "the proxy did not accept the connection. It must be an HTTP CONNECT proxy: " +
			"a SOCKS listener is answered with an HTTP request and fails exactly like this, " +
			"even when the proxy itself is healthy"
	case strings.Contains(tail, "Proxy asked for credentials, none provided"):
		return "the proxy demanded authentication and none was configured; put them in the " +
			"proxy URL as http://user:password@host:port"
	case strings.Contains(tail, "Could not parse the proxy URL"):
		return "the proxy URL could not be read; it wants the form http://host:port"
	case strings.Contains(tail, "Could not load legacy crypto provider"):
		// The statically linked sstpc asks OpenSSL for the legacy provider, and a
		// static musl binary cannot dlopen anything at all, so this fails on EVERY host
		// regardless of what is installed. It is a bundle defect rather than a
		// configuration mistake, and saying so is the only way an operator stops looking
		// for the cause on their own machine.
		return "the bundled sstpc cannot start: its OpenSSL wants the legacy provider, which a fully " +
			"static build has no way to load. This is a defect in the sstpc bundle and no setting here " +
			"can work around it"
	case strings.Contains(tail, "Could not initialize secure socket layer"),
		strings.Contains(tail, "Could not initialize the client"):
		return "sstpc could not start its TLS layer, so the connection was never attempted"
	case strings.Contains(tail, "certificate"), strings.Contains(tail, "Certificate"):
		return "the server's TLS certificate was not accepted: give the CA that signed it, " +
			"or allow an unverified certificate if this gateway is self-signed"
	case strings.Contains(tail, "MPPE required but peer negotiation failed"),
		strings.Contains(tail, "MPPE required, but MS-CHAP[v2] auth not performed"):
		return "the server would not encrypt the link (MPPE), and SSTP cannot answer the crypto " +
			"binding without it; check that the account is allowed MS-CHAPv2"
	case strings.Contains(tail, "MPPE required but kernel has no support"):
		return "the kernel has no MPPE support (the ppp_mppe module is missing), so no SSTP call can complete here"
	case strings.Contains(tail, "authentication failed"), strings.Contains(tail, "Authentication failed"),
		strings.Contains(tail, "MS-CHAP authentication failed"):
		return "the server rejected the username or password"
	case strings.Contains(tail, "Could not open socket to communicate with sstp-client"),
		strings.Contains(tail, "Could not connect to sstp-client"):
		return "the pppd plugin could not reach sstpc over its unix socket, so the crypto binding " +
			"cannot be computed and the server will drop the call"
	case strings.Contains(tail, "Connection refused"):
		return "nothing answered TLS at that address"
	case strings.Contains(tail, "No route to host"), strings.Contains(tail, "Network is unreachable"):
		return "the server address is not reachable from this host"
	case strings.Contains(tail, "Modem hangup"), strings.Contains(tail, "Connection terminated"):
		return "the server closed the call, which after a successful login is what a rejected " +
			"crypto binding looks like"
	}
	return ""
}
