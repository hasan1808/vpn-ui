package service

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/hasan1808/pro-ui/backend"
)

// OpenConnect as an OUTBOUND: the panel dials somebody else's SSL VPN as a client and
// Xray egresses through the tun device that comes up.
//
// The server side (openconnect.go) is ocserv, which is server-only, so this drives the
// bundled `openconnect` binary. It is the widest-reach driver in this set: one client
// speaks seven protocols (anyconnect, nc, gp, pulse, f5, fortinet, array), so the same
// outbound covers Cisco AnyConnect, ocserv, Juniper, GlobalProtect, Pulse, F5 BIG-IP,
// FortiGate and Array gateways.
//
// Three things here are not obvious and each of them is a silent failure if missed.
//
// THE TRUST STORE. This is a static build, and GnuTLS's system trust in it is ONE
// compiled-in path: /etc/ssl/certs/ca-certificates.crt (confirmed with `strings` on the
// binary). That file is a Debian/Ubuntu/Alpine/Arch convention and simply does not
// exist on a RHEL-family host, where the bundle lives at
// /etc/pki/tls/certs/ca-bundle.crt. Fedora, AlmaLinux and CentOS are in this project's
// validated target matrix, so on a third of the supported distributions openconnect
// would reject every gateway certificate ever presented to it, with an error that
// reads like the gateway's fault. So the host is probed for its real bundle and
// --cafile is passed explicitly. See ocOutCABundle, which the SSTP driver shares
// because its client has the identical defect.
//
// THE SCRIPT. openconnect configures NOTHING itself: address, MTU, routes and DNS are
// all delegated to a vpnc-compatible script, and a run without --script authenticates,
// creates a tun device with no address, and carries nothing. So the bundled vpnc-script
// is mandatory, and backend.VpncScriptPath() is where it lands.
//
// THE SCRIPT IS ALSO THE HAZARD. That same script's do_connect ends in
// `set_ipv4_default_route`, which is `ip route replace default dev <tun>` in the MAIN
// table: the whole host moved into somebody else's VPN, including the panel's listener,
// the operator's SSH session and the tunnel's own outer TLS, which then loops. Nothing
// here wants that. Egress through this tunnel is opt-in per Xray outbound
// (SO_BINDTODEVICE plus the private table the framework installs), so the host's
// routing table must be left exactly as it was found. See writeGuard for how that is
// arranged without forking the script.
const (
	// ocOutIfPrefix names the client's tun devices. It cannot be confused with the
	// SERVER's "ocserv-<id>" (openconnect.go), which matters on any box that resells
	// what it buys, and it is short enough to leave a readable tag inside IFNAMSIZ.
	ocOutIfPrefix = "occ-"
	// ocOutIfMax is IFNAMSIZ-1: 16 bytes including the NUL. openconnect hands the name
	// straight to TUNSETIFF, so a longer one fails at device-open time.
	ocOutIfMax = 15

	// ocOutConfDir holds one directory per tunnel: the generated config, the password
	// file, the launcher and the routing guard. Clear of /etc/ocserv, which the server
	// side owns.
	ocOutConfDir = "/etc/openconnect"

	// ocOutUpTimeout bounds the wait for the tun device. openconnect only creates it
	// after the TLS handshake, the authentication form and the tunnel negotiation have
	// all completed, so "the device appeared" is a real proxy for "connected" rather
	// than a formality. It is also a panel-boot cost, because InitVpnOutbound raises
	// tunnels one at a time before Xray starts.
	ocOutUpTimeout = 45 * time.Second
	ocOutPoll      = 500 * time.Millisecond

	// ocOutFingerprintMark introduces the settings fingerprint in the generated config.
	// A '#' comment, which openconnect's config parser skips.
	ocOutFingerprintMark = "# vpn-ui-settings = "
)

// ocOutProtocols is what this build speaks, taken from `openconnect --version`. Kept
// as an allowlist rather than passed through, because an unknown --protocol is a fatal
// startup error and this way it is refused while the modal is still open.
var ocOutProtocols = []string{"anyconnect", "nc", "gp", "pulse", "f5", "fortinet", "array"}

// ocOutSettings is the OpenConnect slice of one outbound tunnel's opaque Settings blob.
type ocOutSettings struct {
	// Server is handed to openconnect verbatim: host, host:port, or a full URL. The
	// path matters for some gateways (GlobalProtect portals, ocserv behind a prefix).
	Server string `json:"server"`

	// Protocol selects the dialect. Empty means anyconnect, which is also what ocserv
	// speaks, so an operator dialing another vpn-ui box leaves it alone.
	Protocol string `json:"protocol"`

	Username string `json:"username"`
	Password string `json:"password"`
	// Authgroup is the gateway's realm/domain/tunnel-group dropdown. Wrong or missing,
	// most gateways answer with a form this client cannot fill in unattended.
	Authgroup string `json:"authgroup"`

	// TotpSecret turns on openconnect's software token, for a gateway that appends a
	// one-time code to the password.
	TotpSecret string `json:"totpSecret"`

	// Certificate authentication, as inline PEM. Either alone or alongside a password,
	// which several gateways require together.
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	KeyPassword string `json:"keyPassword"`

	// CaCert is the PEM that signed the gateway certificate, for a private CA or a
	// self-signed gateway (an ocserv inbound on another vpn-ui self-signs by default).
	CaCert string `json:"caCert"`
	// ServerCert pins one certificate by fingerprint, in openconnect's own
	// "pin-sha256:..." form. It is the right answer for a self-signed gateway: it
	// authenticates the exact server instead of trusting a CA that signs for everyone.
	ServerCert string `json:"serverCert"`

	// NoDtls drops the UDP data channel and carries everything over TLS. Slower, and
	// the only thing that works where UDP is blocked.
	NoDtls bool `json:"noDtls"`

	// The OUTER connection to the gateway, dialled through a proxy instead of straight
	// out of the host's WAN.
	//
	// This is the only mechanism there is for a VPN outbound whose carrier is an
	// ordinary Xray outbound. sockopt.dialerProxy is on the wrong side of the tunnel:
	// it makes Xray hand the traffic to another outbound instead of binding this
	// device, so the exit address becomes the proxy's and the tunnel is skipped
	// entirely (vpnOutStreamSettings deletes it for that reason). Wrapping the outer
	// connection, which is what openconnect's own --proxy does, is the version of the
	// wish that works, and the exit address stays the gateway's.
	//
	// ProxyType is the scheme, and openconnect is stricter than it looks: measured
	// against the bundled v9.21, `socks4://` is refused outright with "Only http or
	// socks(5) proxies supported", and a URL with NO scheme is silently treated as
	// http. So the scheme is a choice between exactly two values and is always written.
	//
	// DTLS: openconnect refuses the UDP data channel whenever a proxy is set ("No DTLS
	// when connected via proxy") and falls back to TLS on its own. NoDtls is
	// deliberately NOT implied from this - see ocOutRenderConfig.
	//
	// omitempty on all five is load-bearing rather than tidiness. pppOutFingerprintOf
	// hashes the MARSHALLED struct, so a new field that marshals as `"proxy":""` would
	// change the fingerprint of every tunnel that already exists, and the first Up
	// after the upgrade would tear down and redial every live OpenConnect outbound for
	// a setting nobody touched.
	ProxyType string `json:"proxyType,omitempty"`
	Proxy     string `json:"proxy,omitempty"`
	ProxyPort int    `json:"proxyPort,omitempty"`
	// ProxyUser/ProxyPass go into the URL's userinfo, percent-encoded, because
	// openconnect has no separate option for them. That is safe here and only here:
	// the URL is written into the 0600 config file and never onto a command line, so
	// the credentials do not reach `ps` (see writeConfig's header).
	ProxyUser string `json:"proxyUser,omitempty"`
	ProxyPass string `json:"proxyPass,omitempty"`

	Mtu int `json:"mtu"`
}

// ocOutProxyTypes is what this openconnect speaks, verified by running the bundled
// v9.21: `http` and `socks5` connect, `socks` is an accepted alias for socks5, and
// `socks4` is rejected at startup with "Only http or socks(5) proxies supported".
// Kept to the two an operator actually picks between.
var ocOutProxyTypes = []string{"socks5", "http"}

// ocOutProxyDefaultPort is what a blank port box means, per scheme.
//
// A default is needed because openconnect's own is wrong for both: internal_parse_url
// falls back to 80 whatever the scheme is, so a blank port on a SOCKS proxy dials port
// 80 and fails with a socks-level error that names nothing. 1080 is the registered
// SOCKS port and what the OpenVPN driver already defaults to, so the two forms agree.
func ocOutProxyDefaultPort(scheme string) int {
	if scheme == "http" {
		return 8080
	}
	return 1080
}

type ocOutDriver struct{}

var _ VpnOutSecrets = (*ocOutDriver)(nil)
var _ VpnOutServer = (*ocOutDriver)(nil)

func init() { RegisterVpnOutDriver(VpnOutOpenConnect, &ocOutDriver{}) }

// SecretKeys names every credential here, all four of which were previously served to
// the browser in cleartext by /vpnoutbound/list: the account password, the client
// certificate's private key, that key's passphrase, and the TOTP seed. The seed is the
// worst of them, because it is the whole second factor rather than one code from it.
//
// `cert`, `caCert` and `serverCert` stay visible: a certificate, the CA that signed the
// gateway's, and a public-key fingerprint are all public by construction, and they are
// what an operator reads back when a gateway refuses the handshake.
//
// `proxyPass` is here for the same reason the OpenVPN driver's socksProxyPass is: it
// authenticates to a different machine from the gateway, but it is still a password and
// /vpnoutbound/list is what the outbound table is drawn from. `proxyUser` stays visible,
// like every other username in this package.
func (d *ocOutDriver) SecretKeys() []string {
	return []string{"password", "key", "keyPassword", "totpSecret", "proxyPass"}
}

func (d *ocOutDriver) parse(cfg VpnOutboundConfig) (*ocOutSettings, error) {
	s := &ocOutSettings{}
	if len(cfg.Settings) > 0 {
		if err := json.Unmarshal(cfg.Settings, s); err != nil {
			return nil, fmt.Errorf("openconnect outbound %q: unreadable settings: %w", cfg.Tag, err)
		}
	}
	s.Server = strings.TrimSpace(s.Server)
	s.Protocol = strings.ToLower(strings.TrimSpace(s.Protocol))
	s.Username = strings.TrimSpace(s.Username)
	s.Authgroup = strings.TrimSpace(s.Authgroup)
	s.TotpSecret = strings.TrimSpace(s.TotpSecret)
	s.ServerCert = strings.TrimSpace(s.ServerCert)
	s.ProxyType = strings.ToLower(strings.TrimSpace(s.ProxyType))
	s.Proxy = strings.TrimSpace(s.Proxy)
	s.ProxyUser = strings.TrimSpace(s.ProxyUser)
	// With no proxy host there is no proxy, so the scheme and port are noise. Clearing
	// them is what keeps a tunnel that uses no proxy hashing to the value it hashed
	// before this feature existed: the form's scheme box has a default and posts
	// "socks5" whether or not it is used, and a tunnel re-saved with nothing changed
	// must not fingerprint differently and redial. The credentials are deliberately
	// left alone so Validate can still name a half-filled form.
	if s.Proxy == "" {
		s.ProxyType = ""
		s.ProxyPort = 0
	}
	return s, nil
}

// Available reports whether an OpenConnect outbound can run here at all.
//
// backend.ClientAvailable covers the binary AND vpnc-script, and names whichever is
// actually missing: without the script the tunnel authenticates and then carries no
// traffic, which is not a failure anyone would attribute to a missing file. Asked at
// SAVE time about a config that may never be raised, so it only looks; the extraction
// happens in Up.
//
// Nothing installable can answer that, and the message says so rather than leaving the
// operator to try. The panel's OpenConnect core installs ocserv, which is the SERVER;
// Up runs backend.ClientPath alone, so a distribution openconnect is not consulted
// either. The only fix is a build that carries the client for this architecture.
// ServerHost names what the outer TLS goes to, so this tunnel can be carried inside
// another. The framework strips the scheme and the path: `server` is handed to
// openconnect verbatim and is routinely a full URL, while a rule selects on the address
// alone.
//
// The proxy wins when there is one, for the same reason it does in the OpenVPN driver:
// with a proxy configured the client never sends a packet to the gateway, so a rule
// naming the gateway would match nothing and the tunnel would quietly not be carried.
func (d *ocOutDriver) ServerHost(cfg VpnOutboundConfig) (string, error) {
	s, err := d.parse(cfg)
	if err != nil {
		return "", err
	}
	if s.Proxy != "" {
		return s.Proxy, nil
	}
	return s.Server, nil
}

func (d *ocOutDriver) Available() (bool, string) {
	ok, why := backend.ClientAvailable(backend.OpenconnectClient)
	if ok {
		return true, ""
	}
	return false, why + ". No package or core supplies it: the driver runs the bundled client only, " +
		"so this needs a vpn-ui build for " + runtime.GOARCH
}

// Validate refuses a config while the modal is still open. Everything decidable
// without touching the network is decided here, because the alternative is a
// forty-five second wait ending in a timeout that explains nothing.
func (d *ocOutDriver) Validate(cfg VpnOutboundConfig) error {
	s, err := d.parse(cfg)
	if err != nil {
		return err
	}
	if s.Server == "" {
		return errors.New("the gateway address is required")
	}
	if s.Protocol != "" {
		ok := false
		for _, p := range ocOutProtocols {
			if p == s.Protocol {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("protocol %q is not one this openconnect build speaks (%s)",
				s.Protocol, strings.Join(ocOutProtocols, ", "))
		}
	}
	if s.Username == "" && strings.TrimSpace(s.Cert) == "" {
		return errors.New("give a username, or a client certificate to authenticate with")
	}
	if (strings.TrimSpace(s.Cert) == "") != (strings.TrimSpace(s.Key) == "") {
		return errors.New("a client certificate needs its private key, and a key needs its certificate")
	}
	// Every one of these becomes one line of an openconnect config file, whose parser
	// takes the rest of the line as the value: a newline would forge an option rather
	// than be part of the value it was typed into.
	for label, v := range map[string]string{
		"server":                    s.Server,
		"username":                  s.Username,
		"authgroup":                 s.Authgroup,
		"TOTP token":                s.TotpSecret,
		"pinned server certificate": s.ServerCert,
		"key password":              s.KeyPassword,
	} {
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("the %s cannot contain line breaks", label)
		}
	}
	// The password is read from a file on stdin, one line, so a newline inside it would
	// silently truncate what is sent.
	if strings.ContainsAny(s.Password, "\r\n") {
		return errors.New("the password cannot contain line breaks")
	}
	for label, pem := range map[string]string{
		"CA certificate":     s.CaCert,
		"client certificate": s.Cert,
		"private key":        s.Key,
	} {
		if strings.TrimSpace(pem) != "" && !strings.Contains(pem, "-----BEGIN") {
			return fmt.Errorf("the %s does not look like PEM (no -----BEGIN----- line)", label)
		}
	}
	if s.ServerCert != "" && !strings.Contains(s.ServerCert, ":") {
		return errors.New("the pinned server certificate must be an openconnect fingerprint, " +
			"such as pin-sha256:<base64> or sha256:<hex>")
	}
	if s.Mtu != 0 && (s.Mtu < 576 || s.Mtu > 1500) {
		return fmt.Errorf("mtu %d is outside 576..1500", s.Mtu)
	}
	return ocOutValidateProxy(s)
}

// ocOutValidateProxy checks the proxy fields, which are one setting spread over five
// boxes. Every shape refused here fails at dial time as something that names the
// gateway rather than the proxy, forty-five seconds later.
func ocOutValidateProxy(s *ocOutSettings) error {
	host := strings.TrimSpace(s.Proxy)
	if host == "" {
		// Credentials pointing at nothing are a half-filled form, not a proxy: the URL
		// would never be written and the operator would be left believing it was.
		if s.ProxyUser != "" || strings.TrimSpace(s.ProxyPass) != "" {
			return errors.New("the proxy has credentials but no address, so nothing would be " +
				"dialled through it. Give the proxy's host, or clear the credentials")
		}
		return nil
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("the proxy address %q has whitespace in it; it is one host or address, "+
			"and the port goes in its own box", s.Proxy)
	}
	// A scheme typed into the host box would end up as socks5://http://host, which
	// openconnect parses as a host called "http" and then cannot resolve.
	if strings.Contains(host, "://") {
		return fmt.Errorf("the proxy address %q carries a scheme; the host goes here on its own "+
			"and HTTP or SOCKS5 is chosen in the box beside it", s.Proxy)
	}
	if s.ProxyType != "" {
		ok := false
		for _, t := range ocOutProxyTypes {
			if t == s.ProxyType {
				ok = true
				break
			}
		}
		if !ok {
			// socks4 is the one an operator will reach for and it is genuinely absent:
			// openconnect refuses it at startup rather than falling back.
			return fmt.Errorf("proxy type %q is not one openconnect speaks (%s); socks4 in "+
				"particular is refused by the client itself", s.ProxyType,
				strings.Join(ocOutProxyTypes, ", "))
		}
	}
	if s.ProxyPort < 0 || s.ProxyPort > 65535 {
		return fmt.Errorf("the proxy port %d is outside 0-65535", s.ProxyPort)
	}
	if s.ProxyUser == "" && strings.TrimSpace(s.ProxyPass) != "" {
		return errors.New("the proxy password has no username with it; both go into the proxy " +
			"URL together and a password on its own is never sent")
	}
	// They are percent-encoded into the URL, so a line break could not forge a second
	// config directive. Refused anyway: it is a paste artefact every time, and it would
	// otherwise be sent to the proxy as a literal newline inside the password.
	if strings.ContainsAny(s.ProxyUser, "\r\n") || strings.ContainsAny(s.ProxyPass, "\r\n") {
		return errors.New("the proxy username and password cannot contain line breaks")
	}
	return nil
}

// ocOutProxyScheme is the scheme actually written, defaulting a blank choice to socks5.
//
// socks5 rather than http as the default because it is the one that carries anything:
// an HTTP proxy only does CONNECT, and while that is all this outer TLS connection
// needs, a SOCKS5 listener is what an operator running Xray already has (every socks
// inbound in this panel is one).
func ocOutProxyScheme(t string) string {
	if t == "http" {
		return "http"
	}
	return "socks5"
}

// ocOutProxyURL renders the proxy as the single URL openconnect takes, or "" when there
// is none.
//
// The scheme is always written, because a URL without one is silently taken as http and
// a SOCKS listener answering an HTTP CONNECT fails as a hang rather than as an error.
// The port is always written for the reason ocOutProxyDefaultPort gives.
//
// net/url builds the userinfo rather than string concatenation, because openconnect
// percent-DECODES both halves: measured against v9.21, `bo%40b:s%3Acr3t@` arrives at
// the proxy as `bo@b:s:cr3t`. Pasting a password containing % or @ raw would therefore
// send a different password than the one that was typed, or split the URL at the wrong
// character. url.UserPassword escapes exactly the set that survives that round trip.
func ocOutProxyURL(s *ocOutSettings) string {
	host := strings.TrimSpace(s.Proxy)
	if host == "" {
		return ""
	}
	scheme := ocOutProxyScheme(s.ProxyType)
	port := s.ProxyPort
	if port <= 0 {
		port = ocOutProxyDefaultPort(scheme)
	}
	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port))}
	if s.ProxyUser != "" {
		u.User = url.UserPassword(s.ProxyUser, s.ProxyPass)
	}
	return u.String()
}

// Up dials the gateway and returns the tun device, only once the kernel actually has
// it and it carries an address.
func (d *ocOutDriver) Up(cfg VpnOutboundConfig) (string, error) {
	s, err := d.parse(cfg)
	if err != nil {
		return "", err
	}
	if err := d.Validate(cfg); err != nil {
		return "", err
	}
	name := pppOutSafeName(cfg.Tag)
	iface := ocOutIfName(cfg.Tag)
	dir := ocOutDir(name)
	proc := ocOutProcName(name)

	// Idempotence, which Up is required to have: it is called on save, at boot and on
	// every reconcile, and a redial would drop every connection Xray currently holds.
	// Keyed on a fingerprint of the settings rather than on the tunnel merely being
	// alive, because returning early on a live-but-stale tunnel would report a changed
	// password as saved while the old one stayed in use.
	if procMgr.IsRunning(proc) && ocOutStoredFingerprint(dir) == pppOutFingerprintOf(s) {
		if ready, _ := ocOutIfaceReady(iface); ready {
			return iface, nil
		}
	}

	// The binaries are embedded and nothing else in the panel lays the client-side ones
	// down: no core owns them, so without this they never reach disk. Cheap and
	// idempotent, and it also re-points the compiled-in vpnc-script symlink, which goes
	// stale if the panel binary moves.
	if err := backend.EnsureClients(); err != nil {
		return "", fmt.Errorf("could not unpack the bundled VPN clients: %w", err)
	}
	bin := backend.ClientPath(backend.OpenconnectClient)
	if bin == "" {
		return "", errors.New("the openconnect client is not on disk and is not bundled for this architecture")
	}
	script := backend.VpncScriptPath()
	if script == "" {
		// Worth its own sentence: openconnect would run, authenticate, create a tun
		// device and then carry nothing, because it configures none of it itself.
		return "", errors.New("vpnc-script is missing, and openconnect delegates every route, address " +
			"and MTU to it, so the tunnel would come up carrying no traffic")
	}

	// Reap daemons orphaned by a panel that died without a clean shutdown, before our
	// own child exists: it pkills by binary path and by process name, and letting it
	// fire later would shoot a live session down.
	migrateFromSystemd()

	if err := d.writeFiles(dir, bin, script, iface, s); err != nil {
		return "", err
	}

	// Where THIS attempt's output starts. The ring buffer survives a restart under the
	// same name, so without a mark a stale "Login failed" from the run that made the
	// operator fix their password would fail the very save that fixed it.
	logMark := pppOutLogLines(procMgr.Logs(proc))

	// The launcher rather than the binary, because the password reaches openconnect on
	// stdin and procmgr does not give a child one. See ocOutWriteLauncher.
	if err := procMgr.Start(proc, ocOutLauncher(dir), nil, nil, dir); err != nil {
		return "", fmt.Errorf("start the openconnect client for %q: %w", cfg.Tag, err)
	}

	if err := d.waitReady(proc, iface, logMark); err != nil {
		// Do not leave it running. procmgr restarts a child that exits, so a config that
		// can never work (a rejected password, an unreachable gateway, an unverifiable
		// certificate) would otherwise retry every five seconds forever while the panel
		// reports the save as failed and nothing on screen suggests a process is still
		// there.
		_ = d.Down(cfg)
		return "", err
	}
	return iface, nil
}

// Down stops the client and clears up after it.
func (d *ocOutDriver) Down(cfg VpnOutboundConfig) error {
	name := pppOutSafeName(cfg.Tag)
	iface := ocOutIfName(cfg.Tag)
	_ = procMgr.Stop(ocOutProcName(name))

	// openconnect destroys its tun on the way out (it runs the script with
	// reason=disconnect and closes the device). Give it a moment before forcing the
	// issue: deleting a device out from under a still-exiting client is how a name comes
	// back a second later with nothing behind it.
	for i := 0; i < 20; i++ {
		if _, err := netlink.LinkByName(iface); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if link, err := netlink.LinkByName(iface); err == nil {
		_ = netlink.LinkDel(link)
	}
	// The directory holds the password in clear and a copy of the private key, and Up
	// rewrites every byte of it, so there is nothing to keep and a real reason not to.
	_ = os.RemoveAll(ocOutDir(name))
	return nil
}

// Status reports the supervised client and the kernel device separately, because they
// come apart in practice: a crash-looping client is alive every five seconds and never
// has a device, and a client that lost its gateway keeps the device while it reconnects.
func (d *ocOutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	name := pppOutSafeName(cfg.Tag)
	proc := ocOutProcName(name)
	iface := ocOutIfName(cfg.Tag)
	running := procMgr.IsRunning(proc)
	ready, addr := ocOutIfaceReady(iface)
	logs := procMgr.Logs(proc)

	var parts []string
	if running {
		parts = append(parts, "client running")
	} else {
		parts = append(parts, "CLIENT STOPPED")
	}
	switch {
	case ready:
		parts = append(parts, iface+" up, address "+addr)
	case ocOutIfacePresent(iface):
		parts = append(parts, iface+" PRESENT BUT NOT CONFIGURED")
	default:
		parts = append(parts, iface+" NOT PRESENT")
	}
	if link, err := netlink.LinkByName(iface); err == nil {
		if st := link.Attrs().Statistics; st != nil {
			parts = append(parts, fmt.Sprintf("rx %s, tx %s", pppOutBytes(st.RxBytes), pppOutBytes(st.TxBytes)))
		}
	}
	if tell := ocOutLogTell(logs); tell != "" {
		parts = append(parts, tell)
	}
	detail := strings.Join(parts, ", ")
	if last := pppOutLastLines(logs, 5); last != "" {
		detail += "\n" + last
	}
	return running && ready, detail
}

// ---------------------------------------------------------------------------
// naming and paths
// ---------------------------------------------------------------------------

// ocOutIfName maps a tag to a bounded, deterministic device name.
//
// Deterministic because Down and Status are handed nothing but the stored config and
// have to find the same device; bounded because the kernel refuses a longer one and
// TUNSETIFF fails outright rather than truncating. A tag that is already a legal short
// name is kept readable so `ip -s link` means something to a human, and the dash
// separator keeps the readable and hashed forms in disjoint namespaces so a hash can
// never land on a readable name. Neither form can collide with the SERVER's
// "ocserv-<id>": that prefix is six characters and this one is three.
func ocOutIfName(tag string) string {
	safe := pppOutSafeName(tag)
	if len(safe) <= ocOutIfMax-len(ocOutIfPrefix) {
		return ocOutIfPrefix + safe
	}
	return fmt.Sprintf("%s%08x", strings.TrimSuffix(ocOutIfPrefix, "-"), pppOutHash(tag))
}

// ocOutProcName is the procmgr key. The prefix keeps it clear of the server side, which
// owns "ocserv-<id>" (OcservService).
func ocOutProcName(name string) string { return "openconnect-out-" + name }

func ocOutDir(name string) string     { return ocOutConfDir + "/out-" + name }
func ocOutConfFile(dir string) string { return dir + "/openconnect.conf" }
func ocOutPassFile(dir string) string { return dir + "/password" }
func ocOutLauncher(dir string) string { return dir + "/run.sh" }
func ocOutGuard(dir string) string    { return dir + "/vpnc-guard.sh" }
func ocOutCaFile(dir string) string   { return dir + "/ca.pem" }
func ocOutCertFile(dir string) string { return dir + "/client.pem" }
func ocOutKeyFile(dir string) string  { return dir + "/client.key" }

// ---------------------------------------------------------------------------
// the host trust store
// ---------------------------------------------------------------------------

// ocOutCABundles is where the distributions in this project's target matrix keep their
// concatenated CA bundle, most specific convention first. The order is not arbitrary:
// several hosts have more than one of these (RHEL ships /etc/ssl/certs as a symlink
// into /etc/pki, Arch has both the ca-certificates.crt and the cert.pem name), so the
// first hit has to be the one the distribution actually maintains.
var ocOutCABundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Alpine, Arch
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL, AlmaLinux, CentOS
	"/etc/ssl/ca-bundle.pem",                            // openSUSE, SLES
	"/etc/ssl/cert.pem",                                 // Alpine, and the BSD convention
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL family, the extracted source of the above
}

var (
	ocOutCAOnce   sync.Once
	ocOutCACached string
)

// ocOutCABundle returns the host's CA bundle, or "" when none of the known locations
// exists.
//
// It exists because the bundled clients are STATIC builds carrying exactly one
// compiled-in trust path, chosen by whatever distribution the bundle was built on
// (Alpine, so /etc/ssl/certs/ca-certificates.crt). On a RHEL-family host that path is
// absent, and the failure is not "no CA found" but "this certificate is untrusted",
// which reads as the gateway's fault and sends the operator looking in the wrong place
// entirely. Passing the host's real bundle explicitly is what makes verification behave
// the same everywhere.
//
// Shared with the SSTP driver, whose sstpc has the identical defect. One copy, because
// a distribution added to one list and not the other is a difference nobody would ever
// notice until it broke.
//
// Cached: this is asked once per raise and the answer cannot change without the host
// being reinstalled underneath a running panel.
func ocOutCABundle() string {
	ocOutCAOnce.Do(func() {
		for _, p := range ocOutCABundles {
			if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
				ocOutCACached = p
				return
			}
		}
	})
	return ocOutCACached
}

// ocOutPinSelfSigned turns a pasted certificate into openconnect's `servercert` pin,
// but ONLY when that certificate is a self-signed leaf: something the operator got
// from the gateway itself rather than from a certificate authority.
//
// The test is deliberately narrow. A real CA certificate must go on being used as a
// CA, because it signs a leaf this side has never seen and pinning the CA's own key
// would reject the gateway outright. So: it must be self-issued (Issuer == Subject and
// its own signature verifies against its own key) and not a CA. Anything else, a chain
// of several PEMs included, is left alone and returns "".
//
// The pin is RFC 7469's: base64 of the SHA-256 of the DER SubjectPublicKeyInfo, which
// is what openconnect compares against, and what makes the pin survive the gateway
// renewing the certificate around the same key.
func ocOutPinSelfSigned(pemText string) string {
	raw := strings.TrimSpace(pemText)
	if raw == "" {
		return ""
	}
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	// More than one certificate is a chain, so the first is a leaf issued by something
	// further down the file: a bundle, which is a CA file and not a gateway's own cert.
	if b, _ := pem.Decode(rest); b != nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	if cert.IsCA || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return ""
	}
	// CheckSignature, not CheckSignatureFrom. The latter first requires the SIGNER to
	// be a CA with keyCertSign, which a self-signed leaf is not by definition, so it
	// rejects with a constraint violation every certificate this branch exists for.
	// What is being asked here is only "was this signed by the key inside it", which is
	// what makes it self-signed rather than merely self-ISSUED (a name can be copied;
	// the signature cannot).
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// generated files
// ---------------------------------------------------------------------------

// writeFiles lays down everything this tunnel needs: the PEMs, the config, the routing
// guard and the launcher.
func (d *ocOutDriver) writeFiles(dir, bin, script, iface string, s *ocOutSettings) error {
	// 0700, because the directory holds the password and the client private key.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := ocOutWritePem(ocOutCaFile(dir), s.CaCert, 0644); err != nil {
		return err
	}
	if err := ocOutWritePem(ocOutCertFile(dir), s.Cert, 0644); err != nil {
		return err
	}
	if err := ocOutWritePem(ocOutKeyFile(dir), s.Key, 0600); err != nil {
		return err
	}
	if err := d.writeGuard(dir, script); err != nil {
		return err
	}
	if err := d.writeConfig(dir, iface, s); err != nil {
		return err
	}
	// One line, no trailing structure: --passwd-on-stdin reads a single line, so a file
	// that ends without a newline is read the same way and one that contains two lines
	// would silently send only the first. Validate has already refused an embedded
	// newline.
	pass := ""
	if s.Password != "" {
		pass = s.Password + "\n"
	}
	if err := os.WriteFile(ocOutPassFile(dir), []byte(pass), 0600); err != nil {
		return err
	}
	return d.writeLauncher(dir, bin, s)
}

func ocOutWritePem(path, pem string, mode os.FileMode) error {
	if strings.TrimSpace(pem) == "" {
		_ = os.Remove(path)
		return nil
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(pem)+"\n"), mode)
}

// writeConfig renders openconnect's own config file.
//
// EVERYTHING goes in here rather than on the command line, including the options that
// have nothing secret about them, because the ones that do have no other hiding place:
// openconnect deliberately offers no --password (so it cannot end up in `ps`), but it
// does offer --token-secret and --key-password, and those would. A config file is read
// before the command line and is not visible to any other user on the box, so the
// process list shows one thing: `openconnect --config <path>`.
//
// 0600: the file carries the TOTP secret, the private key's passphrase and the proxy
// URL, which has the proxy password inside it.
func (d *ocOutDriver) writeConfig(dir, iface string, s *ocOutSettings) error {
	return os.WriteFile(ocOutConfFile(dir), []byte(ocOutRenderConfig(dir, iface, s)), 0600)
}

// ocOutRenderConfig is the config file's text, split from the write so the generated
// directives can be asserted on without a filesystem.
func ocOutRenderConfig(dir, iface string, s *ocOutSettings) string {
	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui (OpenConnect client outbound) - do not edit\n")
	b.WriteString(ocOutFingerprintMark + pppOutFingerprintOf(s) + "\n")

	if s.Protocol != "" {
		b.WriteString("protocol " + s.Protocol + "\n")
	}
	b.WriteString("server " + s.Server + "\n")
	// A name we chose, so Up can return it the moment the device appears and Down and
	// Status can find it later without parsing a log. openconnect would otherwise take
	// the kernel's next free tunN, which is neither knowable in advance nor stable.
	b.WriteString("interface " + iface + "\n")
	// The guard, not the script itself. See writeGuard.
	b.WriteString("script " + ocOutGuard(dir) + "\n")

	// The proxy, when there is one. Nothing at all is written otherwise, which is what
	// keeps every tunnel that already exists byte-identical.
	//
	// `proxy-auth` is the half of this that is not guessable and that silently costs an
	// operator an afternoon. openconnect DISABLES HTTP Basic to a proxy by default, so
	// an http:// URL carrying credentials authenticates with nothing and stops at
	// "Proxy requested Basic authentication which is disabled by default" - measured
	// against v9.21 and a proxy that offers only Basic: no Proxy-Authorization header is
	// sent at all. The list re-enables Basic without giving up the stronger methods,
	// because openconnect prefers them by its own fixed table order (Negotiate, NTLM,
	// Digest, Basic) rather than by the order written here, so Basic is only ever the
	// fallback. SOCKS5 needs none of this: its username/password sub-negotiation is
	// taken straight from the URL, which was measured against a SOCKS5 server demanding
	// method 0x02.
	//
	// DTLS is deliberately left alone. openconnect logs "No DTLS when connected via
	// proxy" and disables the UDP data channel itself the moment a proxy is set, so
	// writing `no-dtls` here would change nothing about the session and would instead
	// make the tunnel's own Disable DTLS setting disagree with the form: clear the
	// proxy later and the operator would be left on TLS with no field explaining it.
	if proxy := ocOutProxyURL(s); proxy != "" {
		b.WriteString("proxy " + proxy + "\n")
		if ocOutProxyScheme(s.ProxyType) == "http" && s.ProxyUser != "" {
			b.WriteString("proxy-auth digest,ntlm,basic\n")
		}
	}

	// The pin. An explicit one is the operator's; otherwise one is DERIVED from a
	// pasted CA certificate that turns out to be the gateway's own self-signed
	// certificate rather than a CA at all.
	//
	// That case is not exotic, it is what this panel hands out: an ocserv inbound
	// self-signs a leaf (Issuer == Subject, CA:FALSE), the operator exports it and
	// pastes it into the box labelled CA certificate, and `cafile` then cannot work
	// for two independent reasons. It is not a CA, so it cannot anchor a chain; and a
	// self-signed leaf carries whatever name it was minted with, which for older
	// panels was the fixed string "vpn-ui OpenConnect Server" and no subjectAltName at
	// all, so the host check fails even where the trust check is coaxed into passing.
	// The result was a gateway an operator could not reach with the very certificate
	// the panel had given them for it.
	//
	// Pinning that certificate is the right answer rather than a workaround: it
	// authenticates THAT server, where trusting it as a CA would trust anything it
	// ever signs. It is also exactly what `servercert` is for, so nothing new is
	// invented here; the operator is simply not made to compute a SHA-256 of a public
	// key by hand to use a certificate they already hold.
	pin := s.ServerCert
	pinnedFromCa := false
	if pin == "" {
		if pin = ocOutPinSelfSigned(s.CaCert); pin != "" {
			pinnedFromCa = true
		}
	}
	if pin != "" {
		b.WriteString("servercert " + pin + "\n")
	}

	// Trust. An operator-supplied CA wins, because it is the specific answer to "this
	// gateway is signed by a CA that is not public". Otherwise the host's own bundle,
	// because this build's single compiled-in path does not exist everywhere.
	//
	// A certificate we just turned into a pin is NOT offered as a CA as well. It cannot
	// anchor anything (that is why it was pinned), so naming it here could only add a
	// way for the handshake to fail while contributing nothing to the decision the pin
	// has already made. The host bundle still goes in, so a gateway that also has a
	// publicly-trusted chain verifies normally and the pin merely agrees with it.
	switch {
	case !pinnedFromCa && ocOutFileExists(ocOutCaFile(dir)):
		b.WriteString("cafile " + ocOutCaFile(dir) + "\n")
	case ocOutCABundle() != "":
		b.WriteString("cafile " + ocOutCABundle() + "\n")
	}

	if s.Username != "" {
		b.WriteString("user " + s.Username + "\n")
	}
	if s.Authgroup != "" {
		b.WriteString("authgroup " + s.Authgroup + "\n")
	}
	if s.Password != "" {
		b.WriteString("passwd-on-stdin\n")
	}
	if s.TotpSecret != "" {
		b.WriteString("token-mode totp\n")
		b.WriteString("token-secret " + s.TotpSecret + "\n")
	}
	if ocOutFileExists(ocOutCertFile(dir)) {
		b.WriteString("certificate " + ocOutCertFile(dir) + "\n")
		b.WriteString("sslkey " + ocOutKeyFile(dir) + "\n")
		if s.KeyPassword != "" {
			b.WriteString("key-password " + s.KeyPassword + "\n")
		}
	}
	// Fail rather than block. This process has no terminal, so a gateway that asks for
	// anything unanticipated (a second factor, an acceptance form, a group choice that
	// was not configured) would otherwise wait forever on a prompt nobody can see, and
	// the panel would report a timeout with no reason attached.
	b.WriteString("non-inter\n")
	// The synthesized outbound binds one device and Xray egresses IPv4 through it. A
	// negotiated IPv6 address would be a second address family on the same link that
	// nothing here routes, and it would have the guard's job to do all over again.
	b.WriteString("disable-ipv6\n")
	if s.NoDtls {
		b.WriteString("no-dtls\n")
	}
	if s.Mtu > 0 {
		b.WriteString(fmt.Sprintf("mtu %d\n", s.Mtu))
	}
	// Keep trying for an hour before giving up on a gateway that went away, instead of
	// exiting and leaving the reconnection to procmgr, which would tear the tun device
	// down and take every Xray connection through it with it.
	b.WriteString("reconnect-timeout 3600\n")

	return b.String()
}

// writeGuard writes the wrapper openconnect actually calls as its config script.
//
// The bundled vpnc-script is the real one and does the work; this only fixes the
// environment it is handed. The problem it solves is in the script's do_connect:
//
//	if [ -n "$CISCO_SPLIT_INC" ]; then      # install the listed split routes
//	    ...
//	elif [ -n "$INTERNAL_IP4_ADDRESS" ]; then
//	    set_ipv4_default_route              # ip route replace default dev $TUNDEV
//	fi
//
// The `elif` is the hijack: with no split-tunnel list from the gateway (which is the
// normal case, and every commercial provider), the script replaces the HOST's default
// route with the tunnel. Nothing about this outbound wants that, and the damage is not
// recoverable from the panel: the SSH session that was watching it goes with it.
//
// Setting CISCO_SPLIT_INC to 0 is the whole fix. It is non-empty, so the `if` branch
// is taken and the `elif` is never reached; the loop it guards runs zero times, so no
// route is installed either. do_disconnect is written the same way round, so the
// teardown then also skips reset_ipv4_default_route, which is what stops the script
// trying to restore a default route it never replaced.
//
// The rest is the same principle applied to everything else that reaches outside this
// device: the DNS variables (the script would rewrite /etc/resolv.conf and hand the
// remote name resolution for the whole panel), the tunnel's own subnet route, the
// exclude routes, and IPv6, whose default route is installed by a separate branch that
// CISCO_SPLIT_INC does not cover. What is deliberately LEFT alone is VPNGATEWAY: the
// script's host route to the gateway is the anti-loop route, it goes through the
// existing default rather than the tunnel, the script removes it again on disconnect,
// and do_ifconfig uses that address to work out the MTU.
//
// A wrapper rather than a fork of the script: the routing, MTU and address handling in
// vpnc-script is a decade of other people's edge cases and none of it should be
// reimplemented here to change one branch. `exec` rather than a call, so the pid stays
// the same, which is what the script's own VPNPID/PPID detection expects.
func (d *ocOutDriver) writeGuard(dir, script string) error {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Auto-generated by vpn-ui (OpenConnect client outbound) - do not edit.\n")
	b.WriteString("#\n")
	b.WriteString("# Runs the bundled vpnc-script with the routing and DNS it would otherwise\n")
	b.WriteString("# apply to the WHOLE HOST switched off. Egress through this tunnel is opt-in\n")
	b.WriteString("# per Xray outbound (SO_BINDTODEVICE plus a private routing table), so the\n")
	b.WriteString("# host's own routing table and resolver must come out of this unchanged.\n")
	b.WriteString("#\n")
	b.WriteString("# CISCO_SPLIT_INC=0 is the load-bearing line: it takes the script's\n")
	b.WriteString("# split-route branch with an empty list, so the default-route branch below it\n")
	b.WriteString("# is never reached, on connect or on disconnect.\n")
	b.WriteString("CISCO_SPLIT_INC=0\n")
	b.WriteString("export CISCO_SPLIT_INC\n")
	b.WriteString("# No resolv.conf rewrite: the remote does not resolve names for this panel.\n")
	b.WriteString("unset INTERNAL_IP4_DNS INTERNAL_IP6_DNS CISCO_DEF_DOMAIN\n")
	b.WriteString("# No route for the tunnel's own subnet, no exclude routes, no IPv6 default\n")
	b.WriteString("# (that one is a separate branch CISCO_SPLIT_INC does not cover).\n")
	b.WriteString("unset INTERNAL_IP4_NETMASK INTERNAL_IP4_NETADDR INTERNAL_IP4_NETMASKLEN\n")
	b.WriteString("unset CISCO_SPLIT_EXC CISCO_IPV6_SPLIT_INC CISCO_IPV6_SPLIT_EXC\n")
	b.WriteString("unset INTERNAL_IP6_ADDRESS INTERNAL_IP6_NETMASK\n")
	b.WriteString("# exec, not a call: the script identifies the connection by its own pid.\n")
	b.WriteString("exec " + pppOutShellQuote(script) + "\n")
	return os.WriteFile(ocOutGuard(dir), []byte(b.String()), 0700)
}

// writeLauncher writes the script procmgr actually starts.
//
// It exists for one reason: the password has to reach openconnect on STDIN
// (--passwd-on-stdin), because openconnect has no --password option at all, by design,
// so that a password can never appear in the process list. procmgr gives its children
// no stdin, and the alternative ways to supply one are worse: --form-entry puts the
// secret in argv where every user on the box can read it, and passing it through the
// environment puts it in /proc/<pid>/environ. A 0600 file redirected onto stdin is
// neither.
//
// `exec`, so the shell is REPLACED by openconnect: the pid procmgr is supervising is
// openconnect's own, which is what makes its process-group signal, its restart
// detection and its log capture all refer to the right process.
func (d *ocOutDriver) writeLauncher(dir, bin string, s *ocOutSettings) error {
	stdin := "/dev/null"
	if s.Password != "" {
		stdin = ocOutPassFile(dir)
	}
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Auto-generated by vpn-ui (OpenConnect client outbound) - do not edit.\n")
	b.WriteString("# The redirect is the point: openconnect reads the password from stdin so that\n")
	b.WriteString("# it never appears in the process list. See vpnout_openconnect.go.\n")
	b.WriteString(fmt.Sprintf("exec %s --config %s < %s\n",
		pppOutShellQuote(bin), pppOutShellQuote(ocOutConfFile(dir)), pppOutShellQuote(stdin)))
	return os.WriteFile(ocOutLauncher(dir), []byte(b.String()), 0700)
}

// ocOutStoredFingerprint reads back the fingerprint of the running config, or "".
func ocOutStoredFingerprint(dir string) string {
	data, err := os.ReadFile(ocOutConfFile(dir))
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(ln, ocOutFingerprintMark) {
			return strings.TrimSpace(strings.TrimPrefix(ln, ocOutFingerprintMark))
		}
	}
	return ""
}

func ocOutFileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// ---------------------------------------------------------------------------
// bringing the tunnel up
// ---------------------------------------------------------------------------

// waitReady blocks until the tun device exists, is up and has an address, or gives up.
//
// All three conditions matter. openconnect creates the device and then hands it to the
// script, which is what gives it an address, and an address is what source selection
// reads once a socket is pinned to the device: without one the kernel sources packets
// from another interface and the gateway drops them. The log is read in parallel
// because the common failures (a rejected password, an unverifiable certificate, a
// gateway that wants a form) never produce a device at all, and waiting out the full
// timeout to say "it did not appear" throws away the line that says why.
func (d *ocOutDriver) waitReady(proc, iface string, logMark int) error {
	deadline := time.Now().Add(ocOutUpTimeout)
	for {
		if ready, _ := ocOutIfaceReady(iface); ready {
			return nil
		}
		fresh := pppOutLogSince(procMgr.Logs(proc), logMark)
		if tell := ocOutLogTell(fresh); tell != "" {
			return fmt.Errorf("the openconnect client did not connect: %s", tell)
		}
		if !procMgr.IsRunning(proc) {
			return fmt.Errorf("the openconnect client stopped before the tunnel came up:\n%s",
				pppOutLastLines(fresh, 6))
		}
		if time.Now().After(deadline) {
			last := pppOutLastLines(fresh, 6)
			if last == "" {
				last = "no output from the client"
			}
			return fmt.Errorf("the tunnel did not come up on %s within %s. Last log:\n%s",
				iface, ocOutUpTimeout, last)
		}
		time.Sleep(ocOutPoll)
	}
}

// ocOutIfaceReady reports whether the device is usable, and its address.
func ocOutIfaceReady(iface string) (bool, string) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return false, ""
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		return false, ""
	}
	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil || len(addrs) == 0 {
		return false, ""
	}
	return true, addrs[0].IPNet.String()
}

func ocOutIfacePresent(iface string) bool {
	_, err := netlink.LinkByName(iface)
	return err == nil
}

// ocOutLogTell turns the handful of failures worth naming into one sentence. Everything
// else is left to the raw log lines the caller appends: a wrong guess about what a line
// means is worse than showing the line.
func ocOutLogTell(log string) string {
	if log == "" {
		return ""
	}
	tail := pppOutLastLines(log, 80)
	switch {
	// The proxy cases come FIRST, because several of them also produce one of the
	// generic lines below (a proxy that will not carry the connection ends with
	// "Failed to open HTTPS connection", which reads as the gateway's fault) and the
	// first match wins. Every string here is one the bundled v9.21 actually prints.
	case strings.Contains(tail, "Only http or socks(5) proxies supported"),
		strings.Contains(tail, "Unknown proxy type"), strings.Contains(tail, "Failed to parse proxy"):
		return "openconnect would not accept the proxy URL; it speaks http and socks5 only"
	case strings.Contains(tail, "Proxy requested Basic authentication which is disabled by default"):
		return "the HTTP proxy wants Basic authentication and the client refused to send it; " +
			"this is a panel bug rather than a setting, since the generated config should " +
			"already carry proxy-auth"
	case strings.Contains(tail, "Proxy CONNECT request failed"):
		return "the HTTP proxy refused to open a connection to the gateway: usually the wrong " +
			"proxy credentials, or a proxy that does not allow CONNECT to port 443"
	case strings.Contains(tail, "SOCKS proxy error"),
		strings.Contains(tail, "Unexpected connect response from SOCKS proxy"),
		strings.Contains(tail, "Error reading connect response from SOCKS proxy"):
		return "the SOCKS proxy refused to carry the connection to the gateway"
	case strings.Contains(tail, "SOCKS server requested username/password but we have none"),
		strings.Contains(tail, "Password authentication to SOCKS server failed"),
		strings.Contains(tail, "SOCKS server requires authentication"),
		strings.Contains(tail, "SOCKS server requested unknown authentication type"):
		return "the SOCKS proxy would not authenticate this connection; check the proxy " +
			"username and password"
	case strings.Contains(tail, "Failed to reconnect to proxy"):
		return "the proxy stopped answering part way through the connection"
	case strings.Contains(tail, "Login failed"), strings.Contains(tail, "Authentication failed"),
		strings.Contains(tail, "Invalid username or password"):
		return "the gateway rejected the credentials"
	case strings.Contains(tail, "Failed to obtain WebVPN cookie"):
		return "the gateway would not issue a session: usually a wrong password, a wrong " +
			"authentication group, or a second factor this connection cannot answer"
	case strings.Contains(tail, "certificate from VPN server") && strings.Contains(tail, "failed verification"),
		strings.Contains(tail, "Certificate from VPN server"),
		strings.Contains(tail, "certificate verify failed"),
		strings.Contains(tail, "Server certificate verify failed"):
		return "the gateway's certificate did not verify: supply the CA that signed it, or pin the " +
			"certificate by fingerprint if this gateway is self-signed"
	case strings.Contains(tail, "Server requested SSL client certificate"):
		return "the gateway wants a client certificate, and none was configured"
	case strings.Contains(tail, "Cannot handle form"), strings.Contains(tail, "requires input"),
		strings.Contains(tail, "No form handler"):
		return "the gateway asked a question this unattended connection cannot answer; " +
			"an authentication group is the usual missing piece"
	case strings.Contains(tail, "Failed to connect to host"), strings.Contains(tail, "Connection refused"):
		return "nothing answered TLS at that address"
	case strings.Contains(tail, "Failed to open tun device"), strings.Contains(tail, "TUNSETIFF failed"):
		return "the tun device could not be created; check that the tun module is loaded"
	case strings.Contains(tail, "Unknown VPN protocol"):
		return "this openconnect build does not speak the selected protocol"
	case strings.Contains(tail, "Failed to spawn script"), strings.Contains(tail, "vpnc-script"):
		return "the configuration script could not be run, so the tunnel would carry no traffic"
	}
	return ""
}
