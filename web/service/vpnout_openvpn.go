package service

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/goccy/go-json"
)

// OpenVPN as an OUTBOUND: the panel runs the same bundled binary with --client, dials
// somebody else's OpenVPN server, and Xray egresses through the tun device it brings up.
//
// The process is a procmgr CHILD, not a systemd unit, exactly like the server instances in
// openvpn.go: same supervision, same ring-buffer log, same death with the panel.
//
// THE PUSHED DEFAULT ROUTE IS THE DANGEROUS PART, and it is worth being explicit about
// because getting it wrong takes the whole machine off the network, not just this tunnel.
// Almost every commercial OpenVPN server pushes `redirect-gateway def1`, which tells the
// client to install 0.0.0.0/1 and 128.0.0.0/1 over the top of the host's default route. On
// this box that would send EVERYTHING through the tunnel: the panel's own HTTPS listener,
// the operator's SSH session, every other VPN protocol's data plane, and the tunnel's own
// outer packets (which then loop). Nothing about this outbound wants that. Xray's egress is
// steered by SO_BINDTODEVICE, and the routing that backs it is the framework's private
// per-interface table (vpnOutBindEgress), which the MAIN table never sees. The client's own
// idea of routing is therefore not wanted at all, and three independent gates keep it out:
//
//  1. --route-nopull discards every pushed ROUTE-class option, which is the class
//     redirect-gateway, route and redirect-private belong to. It deliberately does NOT
//     discard the pushed ifconfig, so the tun still gets its address.
//  2. --pull-filter ignore for the same directives by name, which catches them even if a
//     future OpenVPN moves one out of the ROUTE class.
//  3. --route-noexec, which stops OpenVPN executing ANY route change, pushed or local. This
//     is the one that covers a `redirect-gateway` written into the operator's own pasted
//     profile, which route-nopull does not touch because it is not a pushed option.
//
// The profile is filtered on the way in as well (ovpnOutFilterProfile), so those directives
// never reach the config file in the first place.
//
// All four are subtractive. This driver installs NO route, rule or table of its own, here or
// anywhere else: it hands back a tun with an address on it and the framework does the rest.
// route-noexec in particular is not a route of ours by another name, it is the switch that
// stops the CLIENT installing any, so it cannot interfere with the private table.
//
// One consequence of taking no pushed routes is worth stating: the pushed DNS servers are
// dropped with them, and nothing here writes resolv.conf. That is correct. Name resolution for
// traffic leaving through this tunnel is Xray's business (the synthesized freedom outbound
// uses domainStrategy UseIP so the address is resolved by the core's own DNS, not the host's),
// and rewriting the host's resolver to a VPN provider's would change name resolution for the
// panel and every other protocol on the box.
const (
	// ovpnOutPrefix names the client tun devices. It cannot collide with the server side's
	// "tun-ovpn-<id>-<u|t>" (openvpn.go), which matters because both live on one host as soon
	// as an operator resells what they buy.
	ovpnOutPrefix = "ovpnc"
	// ovpnOutIfMax is IFNAMSIZ-1: 16 bytes including the NUL terminator. OpenVPN passes the
	// name straight to TUNSETIFF, so exceeding it is an immediate failure to open the device.
	ovpnOutIfMax = 15

	// ovpnOutUpTimeout bounds the wait for the tun device. OpenVPN only opens it after the
	// TLS handshake, authentication and PUSH_REPLY have all completed, so "the device
	// appeared" is a real proxy for "the tunnel is connected" rather than a formality. A
	// working server is up in a few seconds; this is sized for a slow or distant one. It is
	// also a boot cost, because InitVpnOutbound raises tunnels one at a time and Xray starts
	// after them, so every unreachable tunnel delays the panel by this much. That is the
	// reason it is not simply generous.
	ovpnOutUpTimeout = 20 * time.Second
	ovpnOutPoll      = 250 * time.Millisecond
)

// ovpnOutSettings is the OpenVPN slice of one outbound tunnel's opaque Settings blob.
//
// Profile is the primary input on purpose: what an operator actually has is a .ovpn file from
// their provider, not a set of fields, and retyping it into fields is where mistakes come
// from. The discrete fields are the alternative for the case where there is no file, or where
// the file is a template with the credentials handed over separately.
type ovpnOutSettings struct {
	// Profile is a pasted .ovpn, used verbatim apart from the directives this driver owns
	// (see ovpnOutFilterProfile). Inline <ca>/<cert>/<key>/<tls-auth>/<tls-crypt> blocks are
	// passed through untouched, which is how most provider profiles carry their keys.
	Profile string `json:"profile"`

	// Discrete alternative, used when Profile is empty.
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Proto    string `json:"proto"` // udp (default) | tcp
	Ca       string `json:"ca"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	TlsAuth  string `json:"tlsAuth"`
	TlsCrypt string `json:"tlsCrypt"`
	// RemoteCertTls asks the client to require the server EKU on the server certificate. Off
	// by default: it is a real hardening step, but a server whose certificate lacks the EKU
	// fails the handshake with an error most operators read as "the VPN is broken".
	RemoteCertTls bool `json:"remoteCertTls"`

	Username string `json:"username"`
	Password string `json:"password"`

	// SocksProxy dials the OpenVPN server THROUGH a SOCKS5 proxy rather than straight out
	// of the host's own WAN. Blank means no proxy, which is the default and what every
	// existing tunnel keeps.
	//
	// This is the field an operator is reaching for when they put a dialerProxy on a VPN
	// tunnel's sockopt, and it is the only place the wish can be granted. sockopt.dialerProxy
	// sits on the wrong side of the tunnel: it applies to the traffic Xray sends INTO the
	// pinned freedom outbound, and the core answers it by redirecting the dial to another
	// outbound instead of binding the device, so the tunnel is skipped entirely and the exit
	// address becomes the proxy's (see vpnOutStreamSettings, which deletes it). The proxy has
	// to wrap the OUTER OpenVPN connection instead, which is what this does. Measured on the
	// bundled 2.6.12 against a real profile: outer TCP established to the SOCKS proxy
	// (exit 212.8.240.13 NL) and the exit address through the tun still 65.109.217.240 (FI),
	// which is exactly "keep the VPN's exit, dial it through the proxy".
	//
	// UDP IS SUPPORTED and is deliberately not refused. OpenVPN carries `proto udp` over
	// SOCKS5 with UDP ASSOCIATE, and the bundled build does it: measured against the same
	// server, "SOCKS proxy wants us to send UDP to 127.0.0.1:47536" followed by
	// "Initialization Sequence Completed". What it needs is a proxy that ALLOWS UDP
	// ASSOCIATE; one that does not answers the associate request with an error, and OpenVPN
	// logs "recv_socks_reply: Socks proxy returned bad reply" and restarts forever, which
	// ovpnOutLogTell turns into a sentence naming the proxy.
	SocksProxy string `json:"socksProxy"`
	// SocksProxyPort defaults to 1080, which is what OpenVPN itself defaults to when the
	// port argument is left off.
	SocksProxyPort int `json:"socksProxyPort"`
	// SocksProxyUser/Pass are written to their own file, because `socks-proxy` takes
	// credentials only as a path and OpenVPN has no inline form for them.
	SocksProxyUser string `json:"socksProxyUser"`
	SocksProxyPass string `json:"socksProxyPass"`

	// Mtu forces tun-mtu and, because the operator asking for one means they know the path
	// better than the server does, also filters the server's pushed value.
	Mtu int `json:"mtu"`
	// Extra is appended verbatim, for the directive this driver did not think of. It is NOT
	// filtered, so it can also be used to put back something the filter removed. It is also
	// NOT a secret (see SecretKeys), so key material must not be put here; Validate rejects an
	// inline private key or a tls-auth/tls-crypt block rather than leaving that as a rule
	// nobody reads.
	Extra string `json:"extra"`
}

// ovpnOutDriver implements VpnOutDriver for kind "openvpn".
type ovpnOutDriver struct{}

func init() { RegisterVpnOutDriver(VpnOutOpenVPN, ovpnOutDriver{}) }

// SecretKeys names every settings key that must never reach the browser.
//
// `profile` is the important one and it is the whole reason this interface is declared by the
// driver rather than guessed by the framework. A .ovpn is not a document with a secret field
// in it, it is a document that CONTAINS its secrets: providers routinely ship one file with
// <key>, <tls-auth> or <tls-crypt> inline, and masking works per top-level key and cannot
// reach inside a string. So the entire profile is withheld, and the merge on save is what
// makes that survivable: an operator changing the MTU posts no profile at all and keeps the
// stored one.
//
// Deliberately NOT listed:
//
//   - ca and cert. Both are certificates, which are public by design; the far side hands its
//     CA out to everyone who connects. Masking them would mean an operator could never check
//     which CA a tunnel trusts, which is exactly the field worth being able to read.
//   - username. Half a credential, and the SSH outbound facade keeps it visible for the same
//     reason: a form that cannot show whose account a tunnel uses is hard to operate.
//   - extra. It is free text the operator wrote and expects to see and refine, so masking it
//     would make it uneditable in practice. Key material does not belong there, and Validate
//     refuses it outright rather than leaving that as a convention nobody reads.
func (ovpnOutDriver) SecretKeys() []string {
	return []string{"profile", "password", "key", "tlsAuth", "tlsCrypt", "socksProxyPass"}
}

// Available reports whether an openvpn binary can be had on this host, which is the exact
// case VpnOutAvailability exists for: the bundle is embedded per architecture, so on one the
// build does not cover (arm64 today) the binary is simply not in this program and the failure
// is a runtime one. Without this the protocol is offered in the picker, accepted on save, and
// only then reports that it cannot run, which reads as a broken panel rather than a missing
// dependency.
//
// Side-effect free on purpose. ovpnOutBinary extracts the bundle as part of resolving it, and
// this is called to render a picker, so it must answer from what is already there plus what is
// embedded, and never write anything.
//
// backend.Available() is an approximation, and the honest kind: it reports whether ANY daemon
// bundle exists for this architecture rather than whether openvpn specifically is in it, since
// the per-file probe is unexported. Every bundle the build script produces carries openvpn, so
// the case this actually separates is "no bundle for this arch", which is the one that matters.
// A bundle that somehow lacked it would still be caught by Validate with a precise message.
// Installing the OpenVPN CORE is deliberately not suggested here even though the
// catalog has one: it extracts openvpn from the very bundle this build does not carry,
// so it would answer nothing. The distribution package is the fix, and it is a real one
// because ovpnOutBinary prefers a host openvpn over failing.
func (ovpnOutDriver) Available() (bool, string) {
	if backend.DaemonPath("openvpn") != "" || commandExists("openvpn") || backend.Available() {
		return true, ""
	}
	return false, "there is no openvpn here: this build carries no daemon bundle for " + runtime.GOARCH +
		", so the OpenVPN core has nothing to extract either. Install your distribution's openvpn package, " +
		"which this driver will use instead"
}

// ovpnOutIfName maps a tag to a bounded, deterministic device name. Deterministic because
// Down and Status get nothing but the stored config and have to find the same device; bounded
// because the kernel simply refuses a longer one. A tag that is already a legal short name is
// kept readable so `ip -s link` is useful to a human, and the dash separator keeps the two
// forms in disjoint namespaces so a hash can never land on a readable name.
func ovpnOutIfName(tag string) string {
	safe := strings.TrimSpace(tag)
	if len(safe) > 0 && len(safe) <= ovpnOutIfMax-len(ovpnOutPrefix)-1 && ovpnOutPlainName(safe) {
		return ovpnOutPrefix + "-" + safe
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(tag))
	return fmt.Sprintf("%s%08x", ovpnOutPrefix, h.Sum32())
}

func ovpnOutPlainName(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// ovpnOutProcName is the procmgr key. The "openvpn-out-" prefix is load-bearing: the server
// service stops every managed process whose name starts with "openvpn-server-" that no longer
// matches an enabled inbound/transport (OpenVpnService.RestartServices, StopServices), and an
// outbound tunnel would match none of them.
func ovpnOutProcName(iface string) string { return "openvpn-out-" + iface }

// ovpnOutDir holds this tunnel's generated config and credentials. Keyed by interface rather
// than by tag so it is a legal path for any tag the operator types.
func ovpnOutDir(iface string) string { return "/etc/openvpn/out-" + iface }

func ovpnOutParse(cfg VpnOutboundConfig) (*ovpnOutSettings, error) {
	st := &ovpnOutSettings{}
	if len(cfg.Settings) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(cfg.Settings, st); err != nil {
		return nil, fmt.Errorf("openvpn outbound: unreadable settings: %w", err)
	}
	return st, nil
}

// ServerHost names the address the OUTER OpenVPN connection goes to, so this tunnel can
// be carried inside another.
//
// The SOCKS proxy wins when there is one, and that is not a detail: with `socks-proxy`
// set, OpenVPN never sends a packet to the VPN server at all, it talks to the proxy and
// the proxy talks to the server. A rule naming the server would match nothing and the
// tunnel would quietly not be carried, which is the failure mode this whole feature
// exists to remove.
//
// Then the discrete field, then the profile's first `remote`. Same order of precedence
// as ovpnOutBuildConfig, which prefers the profile when there is one - the difference is
// deliberate: `server` is only ever set when there is no profile, so checking it first
// costs nothing and saves parsing a pasted file on every reconcile.
func (ovpnOutDriver) ServerHost(cfg VpnOutboundConfig) (string, error) {
	st, err := ovpnOutParse(cfg)
	if err != nil {
		return "", err
	}
	if p := strings.TrimSpace(st.SocksProxy); p != "" {
		return p, nil
	}
	if s := strings.TrimSpace(st.Server); s != "" {
		return s, nil
	}
	return ovpnOutProfileRemote(st.Profile), nil
}

// ---- binary + capability probes -----------------------------------------------------------

// ovpnOutBinary resolves the openvpn executable, extracting the bundled one if the operator
// has never installed the OpenVPN core.
//
// Extracting has a visible side effect worth knowing about: "installed" is decided elsewhere
// by the binary being on disk (daemonInstalled), so the OpenVPN CORE will start reporting
// itself installed in Core Settings once a client outbound has been raised. That is the lesser
// evil. The alternative is refusing to work at all on a box that is carrying the binary inside
// itself, which no operator would read as anything but a bug.
func ovpnOutBinary() (string, error) {
	if p := backend.DaemonPath("openvpn"); p != "" {
		return p, nil
	}
	if _, err := backend.ExtractOnly([]string{"openvpn"}); err != nil {
		logger.Warning("openvpn outbound: could not extract the bundled openvpn:", err)
	}
	if p := backend.DaemonPath("openvpn"); p != "" {
		return p, nil
	}
	// A host openvpn is a perfectly good fallback and is usually a dynamically linked build
	// with MORE features than the bundle (plugins, dco), so it is preferred over failing.
	// This is also the only path on an architecture that ships no bundle.
	if commandExists("openvpn") {
		return daemonBin("openvpn"), nil
	}
	return "", fmt.Errorf("no openvpn binary: this build ships no bundle for this architecture and none is installed on the host")
}

// The bundle is built --enable-lzo --enable-lz4 (build/backend/build.sh), so it can speak to a
// server that insists on compression. This stays a probe rather than a constant because the
// binary is not always the bundled one: DaemonPath falls back to a host openvpn on an
// architecture that ships no bundle, and a distro build may well have been compiled without
// either library. Same shape as openvpn.go probing ciphers and DCO. `openvpn --version`
// advertises its compiled-in options in brackets: "[SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] ...".
var (
	ovpnOutCompProbe sync.Once
	ovpnOutHasLzo    bool
	ovpnOutHasLz4    bool
)

func ovpnOutCompressionSupport(bin string) (lzo, lz4 bool) {
	ovpnOutCompProbe.Do(func() {
		out, _ := exec.Command(bin, "--version").CombinedOutput()
		// --version exits non-zero by design, so the error is deliberately ignored and only
		// the output is read. Same shape as OpenVpnService.hasDCO.
		ovpnOutHasLzo = strings.Contains(string(out), "[LZO]")
		ovpnOutHasLz4 = strings.Contains(string(out), "[LZ4]")
	})
	return ovpnOutHasLzo, ovpnOutHasLz4
}

// ovpnOutCompressionNeed reports which compression library a profile demands, or "".
//
// Only the algorithm matters, not the directive: `compress` with no argument, `compress stub`
// and `compress stub-v2` negotiate the framing without compressing anything and need no
// library, while `comp-lzo` and `compress lzo` need LZO.
func ovpnOutCompressionNeed(profile string) string {
	for _, d := range ovpnOutDirectives(profile) {
		switch d.name {
		case "comp-lzo":
			if len(d.args) > 0 && strings.EqualFold(d.args[0], "no") {
				continue
			}
			return "lzo"
		case "comp-lz4":
			return "lz4"
		case "compress", "allow-compression":
			if len(d.args) == 0 {
				continue
			}
			switch strings.ToLower(d.args[0]) {
			case "lzo":
				return "lzo"
			case "lz4", "lz4-v2":
				return "lz4"
			}
		}
	}
	return ""
}

// ---- profile parsing ----------------------------------------------------------------------

type ovpnOutDirective struct {
	name string
	args []string
}

// ovpnOutDirectives splits a profile into directives, skipping comments and the contents of
// inline <block>...</block> sections. Skipping the block bodies is not tidiness: a PEM body is
// base64, and a base64 line can begin with any word at all, so treating those lines as
// directives produces phantom matches on whatever the key happens to encode.
func ovpnOutDirectives(profile string) []ovpnOutDirective {
	var out []ovpnOutDirective
	block := ""
	for _, raw := range strings.Split(profile, "\n") {
		line := strings.TrimSpace(raw)
		if block != "" {
			if strings.EqualFold(line, "</"+block+">") {
				block = ""
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			block = strings.Trim(line, "<>")
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		out = append(out, ovpnOutDirective{
			name: strings.ToLower(strings.TrimPrefix(fields[0], "--")),
			args: fields[1:],
		})
	}
	return out
}

// ovpnOutProfileFacts is what a pasted profile says about itself: the handful of shapes the
// panel's own block has to bend around instead of overriding.
//
// Collected in one pass and BEFORE anything is written, because two decisions depend on
// facts from elsewhere in the file: whether the profile's own auth-user-pass line survives
// the filter, and which panel block gets appended at all.
//
// It exists because ovpnOutDirectives cannot answer these on its own. That scanner CONSUMES
// inline block headers and never emits them (a PEM body is base64, and a base64 line can
// begin with any word, so its contents must not be read as directives), which means an
// inline <auth-user-pass>, <tls-auth> or <secret> block is invisible to it. Those three
// blocks are exactly the ones that decide what a profile needs from the panel.
type ovpnOutProfileFacts struct {
	// authDirective is an `auth-user-pass` line, with or without an argument.
	authDirective bool
	// authFile is that line's argument, "" for the bare (interactive) form.
	authFile string
	// authInline is an inline <auth-user-pass> block, which CARRIES the credentials rather
	// than asking for them, so a profile with one needs nothing typed into the panel.
	authInline bool
	// tlsAuthInline is an inline <tls-auth> block. It is directional and has no way to say
	// so; see the key-direction handling in ovpnOutBuildConfig.
	tlsAuthInline bool
	// keyDirection is a `key-direction` line of the profile's own.
	keyDirection bool
	// staticKey is a `secret` directive or an inline <secret> block: a pre-shared static
	// key tunnel with no TLS anywhere in it. OpenVPN refuses `--client` beside one.
	staticKey bool
	// hasIfconfig is an `ifconfig` line. Only interesting in static-key mode, where nothing
	// is pushed and the tunnel's addresses can come from nowhere else.
	hasIfconfig bool
	// hasRemote is a `remote` line, i.e. a server to dial.
	hasRemote bool
}

// ovpnOutProfileRemote is the host of a pasted profile's FIRST `remote` line, or "".
//
// Built on ovpnOutDirectives rather than on the facts scan above, which is the same pass
// but answers a yes/no question: this needs the ARGUMENT, and the directive scanner
// already skips comments and inline block bodies, so a `remote` inside a PEM cannot be
// read as one.
//
// First only. A profile listing several remotes lets the client fail over between them,
// and a routing rule can only name the ones the panel can see; carrying such a tunnel is
// steered to the first and the rest are refused by the reconcile, which says so.
func ovpnOutProfileRemote(profile string) string {
	for _, d := range ovpnOutDirectives(profile) {
		if d.name == "remote" && len(d.args) > 0 {
			return strings.Trim(d.args[0], `"'`)
		}
	}
	return ""
}

func ovpnOutScanProfile(profile string) ovpnOutProfileFacts {
	var f ovpnOutProfileFacts
	block := ""
	for _, raw := range strings.Split(profile, "\n") {
		line := strings.TrimSpace(raw)
		if block != "" {
			if strings.EqualFold(line, "</"+block+">") {
				block = ""
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			block = strings.ToLower(strings.Trim(line, "<>"))
			switch block {
			case "auth-user-pass":
				f.authInline = true
			case "tls-auth":
				f.tlsAuthInline = true
			case "secret":
				f.staticKey = true
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(strings.TrimPrefix(fields[0], "--")) {
		case "auth-user-pass":
			f.authDirective = true
			if len(fields) > 1 {
				f.authFile = strings.Trim(fields[1], `"'`)
			}
		case "key-direction":
			f.keyDirection = true
		case "secret":
			f.staticKey = true
		case "ifconfig":
			f.hasIfconfig = true
		case "remote":
			f.hasRemote = true
		}
	}
	return f
}

// ovpnOutAuthFileUsable reports whether an `auth-user-pass <file>` argument names something
// this driver can honestly leave in place.
//
// Absolute AND present, both. A relative path is resolved against the process working
// directory, which is /etc/openvpn/out-<iface>: that directory is created by this driver and
// holds exactly client.conf and auth.txt, so a relative reference can only ever miss, and
// OpenVPN dies at startup with "--auth-user-pass fails with 'creds.txt'". An absolute path
// may well be a file the operator put on the box themselves, and there is no reason to
// refuse one that is sitting right there.
func ovpnOutAuthFileUsable(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// ovpnOutDropped are the directives stripped out of a pasted profile, in three groups.
//
//   - Ones this driver owns. The device name, the log, the management socket and the
//     credentials file are all decided here and a second opinion in the profile would either
//     win or make the config ambiguous.
//   - Ones that would touch the host's routing table. redirect-gateway and friends are the
//     hijack this whole file is arranged around; --route-noexec is the backstop, but not
//     writing them at all is the primary defence.
//   - Ones that would run code. A .ovpn is a document an operator pastes from a third party,
//     and up/down/route-up/tls-verify all name a program that OpenVPN executes AS ROOT. This
//     driver needs none of them, so the whole class is dropped and script-security is pinned
//     to 0 below, which makes it a policy rather than a filter that has to be exhaustive.
var ovpnOutDropped = map[string]bool{
	"dev": true, "dev-type": true, "dev-node": true,
	"daemon": true, "log": true, "log-append": true, "writepid": true, "status": true,
	"management": true, "management-hold": true, "management-query-passwords": true,
	"management-signal": true, "management-up-down": true, "management-client": true,
	"auth-user-pass": true, "askpass": true, "config": true, "cd": true, "chroot": true,
	"user": true, "group": true,
	"route": true, "route-ipv6": true, "route-gateway": true, "route-metric": true,
	"route-delay": true, "route-nopull": true, "route-noexec": true, "route-up": true,
	"route-pre-down": true, "redirect-gateway": true, "redirect-private": true,
	"block-outside-dns": true, "block-ipv6": true,
	"up": true, "down": true, "up-restart": true, "ipchange": true, "tls-verify": true,
	"client-connect": true, "client-disconnect": true, "learn-address": true,
	"auth-user-pass-verify": true, "script-security": true, "setenv-safe": true,
}

// ovpnOutFilterProfile returns the profile with the owned/dangerous directives removed and
// inline blocks preserved verbatim.
//
// keepAuth spares the profile's own `auth-user-pass` line, which is otherwise owned by the
// panel like every other directive in ovpnOutDropped. Only ovpnOutBuildConfig can decide
// that, because it depends on whether a username was typed and on whether the file the
// directive names is actually on this server.
func ovpnOutFilterProfile(profile string, keepAuth bool) (filtered string) {
	var b strings.Builder
	block := ""
	for _, raw := range strings.Split(profile, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if block != "" {
			b.WriteString(line + "\n")
			if strings.EqualFold(trimmed, "</"+block+">") {
				block = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") && !strings.HasPrefix(trimmed, "</") {
			block = strings.Trim(trimmed, "<>")
			b.WriteString(line + "\n")
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			b.WriteString(line + "\n")
			continue
		}
		fields := strings.Fields(trimmed)
		name := strings.ToLower(strings.TrimPrefix(fields[0], "--"))
		if name == "auth-user-pass" && keepAuth {
			// The credentials live in a file that really is on this server and the panel has
			// none of its own to write, so this line is the whole authentication story for
			// the tunnel. See ovpnOutBuildConfig.
			b.WriteString(line + "\n")
			continue
		}
		if ovpnOutDropped[name] {
			// Left in as a comment rather than deleted, so an operator comparing the
			// generated config against the profile they pasted can see what happened to a
			// line instead of wondering whether the paste truncated.
			b.WriteString("# [vpn-ui] removed, owned by the panel: " + trimmed + "\n")
			continue
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// ---- config generation --------------------------------------------------------------------

// ovpnOutBuildConfig renders the client config: the operator's profile (filtered) or the
// discrete fields, followed by the block this driver owns. The panel's block goes LAST so
// that for the single-valued options OpenVPN resolves by last-one-wins (dev, tun-mtu, verb)
// it is this driver's value that survives even if the filter missed one.
//
// AN IMPORTED PROFILE IS RUN AS WRITTEN. The panel's block adds the device, the routing
// gates and the credentials file, and it adapts to what the profile already is rather than
// insisting on one shape: a static-key profile gets no `client`, a profile carrying its own
// credentials gets no auth-user-pass of ours, and an inline <tls-auth> gets the direction it
// cannot state itself. What is left is the small set of things that genuinely cannot run,
// and each of those returns a sentence naming the missing piece.
func ovpnOutBuildConfig(st *ovpnOutSettings, iface, dir string) (string, error) {
	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui (OpenVPN client outbound) - do not edit\n")

	// Credentials typed into the panel always win: the operator entered them for this
	// tunnel, and the file the panel writes is the only one it can be sure exists.
	typedCreds := strings.TrimSpace(st.Username) != "" || strings.TrimSpace(st.Password) != ""

	var facts ovpnOutProfileFacts
	if strings.TrimSpace(st.Profile) != "" {
		facts = ovpnOutScanProfile(st.Profile)
		// The profile's own `auth-user-pass <file>` is kept only when nothing was typed and
		// the file is really there.
		//
		// THE OLD BEHAVIOUR WAS TO PRETEND. Any auth-user-pass at all, in any form, was
		// commented out and the operator was told to type a username and password, as if
		// the panel had read the file and found it wanting. It never reads it. Two answers
		// are true instead of one lie: a file that exists at an absolute path is honoured
		// as written, and a file that cannot exist is refused with a sentence saying so.
		// Honouring a relative path instead would be the same pretence in the other
		// direction, because the process runs in ovpnOutDir(), which holds nothing but
		// client.conf and auth.txt, so the reference could only ever miss.
		keepAuth := !typedCreds && facts.authFile != "" && ovpnOutAuthFileUsable(facts.authFile)
		if !typedCreds && !keepAuth && facts.authDirective && !facts.authInline {
			if facts.authFile != "" {
				return "", fmt.Errorf("this profile reads its credentials from %q, which is not a file on this "+
					"server (the client runs in %s, and nothing is copied there). Type the username and password "+
					"into the form, or put the file on the server and name it by its absolute path",
					facts.authFile, dir)
			}
			return "", fmt.Errorf("this profile authenticates with a username and password, but none were given")
		}
		b.WriteString(ovpnOutFilterProfile(st.Profile, keepAuth))
	} else {
		proto := ovpnOutProto(st)
		port := st.Port
		if port == 0 {
			port = 1194
		}
		b.WriteString(fmt.Sprintf("remote %s %d %s\n", strings.TrimSpace(st.Server), port, proto))
		b.WriteString(ovpnOutInline("ca", st.Ca))
		b.WriteString(ovpnOutInline("cert", st.Cert))
		b.WriteString(ovpnOutInline("key", st.Key))
		if strings.TrimSpace(st.TlsAuth) != "" {
			b.WriteString(ovpnOutInline("tls-auth", st.TlsAuth))
			// tls-auth is directional and the client is always direction 1. Omitting it is
			// the classic "TLS key negotiation failed" with a perfectly good key.
			b.WriteString("key-direction 1\n")
		}
		b.WriteString(ovpnOutInline("tls-crypt", st.TlsCrypt))
		if st.RemoteCertTls {
			b.WriteString("remote-cert-tls server\n")
		}
	}

	b.WriteString("\n# ---- panel-owned settings, see vpnout_openvpn.go ----\n")
	if facts.staticKey {
		// A --secret profile carries no TLS at all, and `client` expands to `--pull
		// --tls-client`, which OpenVPN refuses beside a static key: "Options error: specify
		// only one of --tls-server, --tls-client, or --secret". Verified against both the
		// bundled 2.6.12 and a host 2.7.6. Forcing `client` therefore made a static-key
		// profile IMPOSSIBLE to run, however correct the file the operator pasted was.
		b.WriteString("# static-key profile (--secret): no `client`, which OpenVPN refuses beside it\n")
	} else {
		b.WriteString("client\n")
	}
	// Forced and deterministic, so Up/Down/Status know the device without parsing the log,
	// and so the synthesized freedom outbound can be bound to it the moment Up returns.
	b.WriteString("dev-type tun\n")
	b.WriteString(fmt.Sprintf("dev %s\n", iface))
	// The three route gates. See the file header; between them a pushed OR a locally written
	// redirect-gateway cannot reach the host routing table. Two of the three are about PUSHED
	// options and so belong only to the TLS path, which is the one that pulls.
	if !facts.staticKey {
		b.WriteString("route-nopull\n")
	}
	b.WriteString("route-noexec\n")
	if facts.staticKey {
		// route-nopull and the pull-filter list are dropped here rather than kept and inert.
		// Both ARE legal without --pull (checked against 2.6.12 and 2.7.6: the config parses
		// and the process gets as far as opening the device), so this is not a syntax
		// concession; it is that static-key mode has no PUSH_REPLY for either of them to
		// filter, and a config full of directives that cannot fire reads as protection that
		// is not there. route-noexec above is the one that still bites in this mode: it is
		// what stops a `route` or `redirect-gateway` arriving through `extra` reaching the
		// host's routing table.
		b.WriteString("# no route-nopull/pull-filter: nothing is pushed without --pull\n")
	} else {
		// pull-filter matches a PREFIX of the pushed option, so "route" alone already covers
		// route-gateway, route-delay and route-ipv6; the longer names are spelled out anyway
		// because this list is what an operator reads to check what is blocked, and a prefix rule
		// they have to know about is not documentation. dhcp-option is here for a different reason:
		// route-nopull already refuses it, but it refuses it LOUDLY, logging
		// "Options error: option 'dhcp-option' cannot be used in this context ([PUSH-OPTIONS])"
		// on every successful connect. Filtering it drops it silently, so the log of a healthy
		// tunnel has no error line in it.
		for _, opt := range []string{"redirect-gateway", "redirect-private", "route", "route-ipv6",
			"block-outside-dns", "block-ipv6", "dhcp-option"} {
			b.WriteString(fmt.Sprintf("pull-filter ignore \"%s\"\n", opt))
		}
	}
	// persist-tun keeps ONE tun device across reconnects. Without it a re-key or a dropped
	// connection closes the device and opens a new one, and although the name comes back the
	// same the ifindex does not: SO_BINDTODEVICE resolves to an index at bind time, so every
	// socket Xray already has through this tunnel would be pinned to a device that no longer
	// exists, and the outbound would stay broken until the core was restarted.
	b.WriteString("persist-tun\n")
	b.WriteString("persist-key\n")
	b.WriteString("nobind\n")
	b.WriteString("resolv-retry infinite\n")
	// Pinned rather than merely filtered, so a script directive that slipped past the filter
	// (or arrived through Extra) is inert instead of running as root. 1 and not 0: level 1
	// still permits the BUILT-IN calls, and an openvpn configured --enable-iproute2 shells
	// out to `ip` to configure the tun device itself, so 0 would stop it bringing its own
	// interface up. The bundled build uses netlink directly and would not care, but a distro
	// binary is a supported fallback here and must not be broken by a hardening flag.
	b.WriteString("script-security 1\n")
	b.WriteString("verb 3\n")
	if facts.tlsAuthInline && !facts.keyDirection {
		// tls-auth is directional and the client is always direction 1. An inline <tls-auth>
		// block has no way to carry a direction, so a provider profile states it on a
		// separate `key-direction 1` line -- and a profile pasted without that line (or one
		// whose provider simply left it out) fails the handshake as "TLS key negotiation
		// failed" with a perfectly good key. The discrete path has always emitted this; the
		// profile path did not, which made the same key work typed in and not pasted in.
		b.WriteString("key-direction 1\n")
	}
	if st.Mtu > 0 {
		b.WriteString(fmt.Sprintf("tun-mtu %d\n", st.Mtu))
		if !facts.staticKey {
			// An operator who sets an MTU knows something about the path that the server does
			// not, so the server's pushed value must not overwrite it. Nothing is pushed in
			// static-key mode, so there is nothing to filter there.
			b.WriteString("pull-filter ignore \"tun-mtu\"\n")
		}
	}
	if typedCreds {
		// A file, never the console: a bare auth-user-pass makes OpenVPN block on a terminal
		// that a supervised child process does not have, which shows up as a tunnel that
		// never connects and a log that stops after "Need username/password".
		b.WriteString(fmt.Sprintf("auth-user-pass %s\n", ovpnOutAuthPath(dir)))
	}
	if host := strings.TrimSpace(st.SocksProxy); host != "" {
		port := st.SocksProxyPort
		if port == 0 {
			port = 1080
		}
		// Written here, in the panel-owned block, and NOT filtered out of the profile. A
		// profile that carries its own socks-proxy keeps it when this field is blank, which
		// is the "run the profile as written" rule the rest of this file follows; when the
		// field is set, this line wins because the block is last and OpenVPN resolves a
		// repeated socks-proxy last-one-wins. Verified against the bundled 2.6.12: two
		// socks-proxy lines parse, and it dials the second.
		if strings.TrimSpace(st.SocksProxyUser) != "" {
			b.WriteString(fmt.Sprintf("socks-proxy %s %d %s\n", host, port, ovpnOutSocksAuthPath(dir)))
		} else {
			b.WriteString(fmt.Sprintf("socks-proxy %s %d\n", host, port))
		}
		// Without this a proxy that is momentarily unreachable is FATAL: OpenVPN treats a
		// SOCKS error as a hard connection failure and, with a single remote and no retry,
		// gives up on the profile instead of coming back. procmgr would restart the child, so
		// the tunnel would recover either way, but only after the panel had already reported
		// the save as failed.
		b.WriteString("socks-proxy-retry\n")
	}
	if extra := strings.TrimSpace(st.Extra); extra != "" {
		b.WriteString("\n# ---- operator extra directives ----\n")
		b.WriteString(extra)
		if !strings.HasSuffix(extra, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

func ovpnOutProto(st *ovpnOutSettings) string {
	switch strings.ToLower(strings.TrimSpace(st.Proto)) {
	case "tcp", "tcp-client":
		return "tcp-client"
	default:
		return "udp"
	}
}

func ovpnOutInline(tag, pem string) string {
	pem = strings.TrimSpace(pem)
	if pem == "" {
		return ""
	}
	return fmt.Sprintf("<%s>\n%s\n</%s>\n", tag, pem, tag)
}

// ovpnOutInlineSecretIn returns the name of the first key-bearing inline block found in a
// free-text field, or "". Only the blocks that carry KEY material are named: <ca> and <cert>
// are certificates, so pasting one here leaks nothing and refusing it would be pedantry.
func ovpnOutInlineSecretIn(s string) string {
	lower := strings.ToLower(s)
	for _, b := range []string{"key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret"} {
		if strings.Contains(lower, "<"+b+">") {
			return b
		}
	}
	return ""
}

func ovpnOutAuthPath(dir string) string { return dir + "/auth.txt" }
func ovpnOutConfPath(dir string) string { return dir + "/client.conf" }

// ovpnOutSocksAuthPath is the SOCKS proxy's own credentials file, kept separate from
// auth.txt because they authenticate to different machines: one to the VPN server, one to
// the proxy in front of it, and a tunnel can need either, both or neither.
func ovpnOutSocksAuthPath(dir string) string { return dir + "/socks-auth.txt" }

// ovpnOutSocksAuthContent is the two-line file `socks-proxy <host> <port> <file>` reads.
// Empty when there is no username, which is also what tells Up to delete the file: a
// leftover from a proxy that used to need credentials would still be read by OpenVPN.
func ovpnOutSocksAuthContent(st *ovpnOutSettings) string {
	if strings.TrimSpace(st.SocksProxy) == "" || strings.TrimSpace(st.SocksProxyUser) == "" {
		return ""
	}
	return st.SocksProxyUser + "\n" + st.SocksProxyPass + "\n"
}

// ovpnOutAuthContent is the two-line credentials file OpenVPN expects. A newline inside
// either field would forge a third line and silently change what is being sent, so they are
// rejected in Validate rather than escaped here.
func ovpnOutAuthContent(st *ovpnOutSettings) string {
	if strings.TrimSpace(st.Username) == "" && strings.TrimSpace(st.Password) == "" {
		return ""
	}
	return st.Username + "\n" + st.Password + "\n"
}

// ---- driver ---------------------------------------------------------------------------------

// Validate refuses a config while the modal is still open. Everything checkable without
// touching the network is checked here, because the alternative is a 25 second wait followed
// by a timeout that says nothing useful.
func (ovpnOutDriver) Validate(cfg VpnOutboundConfig) error {
	st, err := ovpnOutParse(cfg)
	if err != nil {
		return err
	}
	bin, err := ovpnOutBinary()
	if err != nil {
		return err
	}

	profile := strings.TrimSpace(st.Profile)
	if profile == "" {
		if strings.TrimSpace(st.Server) == "" {
			return fmt.Errorf("paste an .ovpn profile, or give the server address")
		}
		if st.Port < 0 || st.Port > 65535 {
			return fmt.Errorf("port %d is outside 0-65535", st.Port)
		}
		// DISCRETE PATH ONLY, and deliberately so. Here the operator is building a config
		// field by field, so an empty CA box is an omission rather than a choice, and there
		// is no other place the certificate could have come from. A pasted profile is
		// judged differently below: see the note there.
		if strings.TrimSpace(st.Ca) == "" {
			return fmt.Errorf("the server's CA certificate is required to verify it")
		}
		if p := strings.ToLower(strings.TrimSpace(st.Proto)); p != "" && p != "udp" && p != "tcp" && p != "tcp-client" {
			return fmt.Errorf("protocol %q is not udp or tcp", st.Proto)
		}
		if (strings.TrimSpace(st.Cert) == "") != (strings.TrimSpace(st.Key) == "") {
			return fmt.Errorf("a client certificate needs its key, and a key needs its certificate")
		}
	} else {
		facts := ovpnOutScanProfile(profile)
		if !facts.hasRemote {
			return fmt.Errorf("this profile has no `remote` line, so there is no server to dial")
		}
		// THERE IS DELIBERATELY NO CA CHECK ON THIS PATH. A pasted profile is run as
		// written, and "no <ca>" is not proof of anything: a static-key profile has no CA
		// by definition, and a TLS one may verify by `peer-fingerprint` instead. Refusing it
		// here is what made an operator's own working .ovpn unimportable. When a profile
		// really is missing the CA it needs, OpenVPN says so in one line at startup and
		// ovpnOutLogTell turns that line into the same sentence this check used to.
		//
		// Nor is there a blanket credentials check any more: ovpnOutBuildConfig, rendered at
		// the end of this function, refuses only the shapes that cannot authenticate at all,
		// and names which one it hit.
		if facts.staticKey && !facts.hasIfconfig {
			// The one thing a static-key profile cannot do without. Nothing is pushed in this
			// mode, so the addresses can only come from the file itself; without them the tun
			// device comes up bare, ovpnOutIfaceReady never sees an address, and the save
			// fails 20 seconds later with a timeout that explains nothing.
			return fmt.Errorf("this static-key profile has no `ifconfig` line, so its tun device would come " +
				"up with no address and nothing could be routed through it; add the `ifconfig <local> <remote>` " +
				"pair the far side gave you")
		}
		// The bundled binary has both libraries, but a HOST openvpn (used where this build
		// ships no bundle) may not, and a server that insists on compression cannot be talked
		// to at all without it. Caught here rather than left to fail at connect time, where it
		// surfaces as an unrecognized-option line buried in the log.
		if need := ovpnOutCompressionNeed(profile); need != "" {
			lzo, lz4 := ovpnOutCompressionSupport(bin)
			if (need == "lzo" && !lzo) || (need == "lz4" && !lz4) {
				return fmt.Errorf("this profile needs %s compression, which this openvpn build does not have. "+
					"Ask the provider for a profile without compression, or install a distro openvpn that has it",
					strings.ToUpper(need))
			}
		}
	}
	if strings.ContainsAny(st.Username, "\r\n") || strings.ContainsAny(st.Password, "\r\n") {
		return fmt.Errorf("the username and password cannot contain line breaks")
	}
	if err := ovpnOutValidateSocks(st); err != nil {
		return err
	}
	if block := ovpnOutInlineSecretIn(st.Extra); block != "" {
		// Secrets are withheld from the panel per top-level key (SecretKeys), and `extra` is
		// deliberately not one of them because the operator has to be able to read back what
		// they typed. That makes it the one place a key could be pasted and then handed
		// straight back to every browser that lists the outbounds. Refusing it closes the hole
		// at the only point that can see inside the string, and points at the field that does
		// get withheld.
		return fmt.Errorf("the extra directives hold an inline <%s> block; key material must go "+
			"in the profile or in the dedicated field, which are the ones kept off the panel", block)
	}
	if st.Mtu != 0 && (st.Mtu < 576 || st.Mtu > 9000) {
		return fmt.Errorf("MTU %d is outside the usable range (576-9000)", st.Mtu)
	}
	// Rendering it is the last check: it is the one that catches a profile whose auth shape
	// only becomes contradictory once the panel's own block is added.
	if _, err := ovpnOutBuildConfig(st, ovpnOutIfName(cfg.Tag), ovpnOutDir(ovpnOutIfName(cfg.Tag))); err != nil {
		return err
	}
	return nil
}

// ovpnOutValidateSocks checks the SOCKS proxy fields, which are one setting spread over four
// boxes and so have several ways to be half-filled.
//
// There is deliberately NO refusal of `proto udp` here. OpenVPN speaks SOCKS5 UDP ASSOCIATE
// and the bundled 2.6.12 brings a udp profile up through a proxy that allows it (measured);
// refusing the pair would break a configuration that works, and would refuse the udp half of
// every provider that ships a tcp and a udp profile. The failure that DOES happen is the
// proxy declining the associate, and that is answered in ovpnOutLogTell, where the client's
// own words are available to name it.
func ovpnOutValidateSocks(st *ovpnOutSettings) error {
	host := strings.TrimSpace(st.SocksProxy)
	user := strings.TrimSpace(st.SocksProxyUser)
	if host == "" {
		// The rest is inert without a host, with ONE exception worth naming rather than
		// ignoring: a password typed with no host reads as a proxy the operator meant to
		// configure and did not finish.
		if user != "" || strings.TrimSpace(st.SocksProxyPass) != "" {
			return fmt.Errorf("the SOCKS proxy has credentials but no address, so nothing would be " +
				"dialled through it; fill in the proxy address or clear its username and password")
		}
		return nil
	}
	if strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("the SOCKS proxy address %q has whitespace in it; it is one host or address, "+
			"and the port goes in its own box", st.SocksProxy)
	}
	if st.SocksProxyPort < 0 || st.SocksProxyPort > 65535 {
		return fmt.Errorf("the SOCKS proxy port %d is outside 0-65535", st.SocksProxyPort)
	}
	if user == "" && strings.TrimSpace(st.SocksProxyPass) != "" {
		// OpenVPN reads the credentials as two lines, username first. A file whose first line
		// is empty authenticates as the empty user, which no proxy accepts and which fails as
		// a generic SOCKS error naming nothing.
		return fmt.Errorf("the SOCKS proxy password has no username with it; OpenVPN sends the two " +
			"together or not at all")
	}
	if strings.ContainsAny(st.SocksProxyUser, "\r\n") || strings.ContainsAny(st.SocksProxyPass, "\r\n") {
		return fmt.Errorf("the SOCKS proxy username and password cannot contain line breaks")
	}
	return nil
}

// Up starts (or adopts) the client and returns the tun device, only once the kernel actually
// has it.
//
// Idempotency needs an explicit guard here, unlike the netlink protocols: procMgr.Start always
// kills and relaunches, so calling it on every reconcile would drop a healthy tunnel every
// time. The generated config is therefore compared with what is already on disk, and an
// unchanged config with a live process and a ready device is left completely alone.
func (ovpnOutDriver) Up(cfg VpnOutboundConfig) (string, error) {
	st, err := ovpnOutParse(cfg)
	if err != nil {
		return "", err
	}
	bin, err := ovpnOutBinary()
	if err != nil {
		return "", err
	}
	iface := ovpnOutIfName(cfg.Tag)
	dir := ovpnOutDir(iface)
	conf, err := ovpnOutBuildConfig(st, iface, dir)
	if err != nil {
		return "", err
	}
	auth := ovpnOutAuthContent(st)
	socksAuth := ovpnOutSocksAuthContent(st)
	name := ovpnOutProcName(iface)

	if ovpnOutUnchanged(dir, conf, auth, socksAuth) && procMgr.IsRunning(name) {
		if ready, _ := ovpnOutIfaceReady(iface); ready {
			return iface, nil
		}
	}

	// modprobe before anything else: without /dev/net/tun OpenVPN dies at device-open time
	// with a message about permissions that sends people looking in the wrong place.
	(&OpenVpnService{}).runCmd("modprobe", "tun")

	// migrateFromSystemd's one-shot cleanup ends with `pkill -KILL -f <openvpn binary path>`,
	// which matches EVERY openvpn on the box including this one. It is a sync.Once, and on a
	// host with no OpenVPN inbound nothing has triggered it yet, so it would otherwise fire
	// later (the first time an operator adds an inbound) and shoot this client down. Running
	// it here, before the child exists, makes that impossible.
	migrateFromSystemd()

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	if auth != "" {
		if err := os.WriteFile(ovpnOutAuthPath(dir), []byte(auth), 0600); err != nil {
			return "", err
		}
	} else {
		_ = os.Remove(ovpnOutAuthPath(dir))
	}
	if socksAuth != "" {
		if err := os.WriteFile(ovpnOutSocksAuthPath(dir), []byte(socksAuth), 0600); err != nil {
			return "", err
		}
	} else {
		_ = os.Remove(ovpnOutSocksAuthPath(dir))
	}
	// 0600: the config can carry an inline private key, and on the discrete path it always
	// does.
	if err := os.WriteFile(ovpnOutConfPath(dir), []byte(conf), 0600); err != nil {
		return "", err
	}

	// The ring buffer survives a restart of the same process name, so the wait below has to
	// know where THIS attempt's output starts: without that, a stale AUTH_FAILED from the run
	// that made the operator fix their password would fail the very save that fixed it.
	logMark := ovpnOutLogLines(procMgr.Logs(name))

	// --suppress-timestamps on the command line rather than in the config, exactly as the
	// server instances are launched: procmgr stamps every captured line itself, so OpenVPN's
	// own timestamp is a second one on the same line.
	args := []string{"--suppress-timestamps", "--config", ovpnOutConfPath(dir)}
	if err := procMgr.Start(name, bin, args, nil, dir); err != nil {
		return "", fmt.Errorf("openvpn outbound %s: %w", cfg.Tag, err)
	}
	if err := ovpnOutWaitReady(name, iface, logMark); err != nil {
		// Stop it rather than leaving it behind. procmgr restarts a child that exits, so a
		// fatally misconfigured client (wrong credentials, unreachable server, an option this
		// build does not have) would otherwise crash-loop every five seconds forever, while
		// the panel reports the save as failed and nothing on screen suggests a process is
		// still running.
		_ = procMgr.Stop(name)
		return "", err
	}
	return iface, nil
}

// ovpnOutUnchanged reports whether the files on disk already say exactly this.
//
// All THREE files, because any one of them changing changes what the client does and the
// answer here is what decides whether a running client is left alone. The SOCKS credentials
// are the newest of the three and the easiest to forget: the proxy's host and port are in
// the config, so those are covered, but rotating only the proxy PASSWORD leaves the config
// byte-identical, and without this line the save would report success and the tunnel would
// go on using the old file.
func ovpnOutUnchanged(dir, conf, auth, socksAuth string) bool {
	have, err := os.ReadFile(ovpnOutConfPath(dir))
	if err != nil || string(have) != conf {
		return false
	}
	if !ovpnOutFileSays(ovpnOutAuthPath(dir), auth) {
		return false
	}
	return ovpnOutFileSays(ovpnOutSocksAuthPath(dir), socksAuth)
}

// ovpnOutFileSays reports whether the file holds exactly want, treating "unreadable" and
// "absent" as the empty string, which is how this driver spells "there should be no file".
func ovpnOutFileSays(path, want string) bool {
	have, err := os.ReadFile(path)
	if err != nil {
		return want == ""
	}
	return string(have) == want
}

// ovpnOutWaitReady blocks until the tun device exists, is up and has an address, or gives up.
//
// All three conditions matter. OpenVPN creates the device and configures it in one step after
// PUSH_REPLY, and an address is what source selection reads once a socket is pinned to the
// device: a device with no address makes the kernel source packets from another interface, and
// the far end drops them. The log is watched in parallel because the common failures (bad
// credentials, unreachable server, an option this build lacks) never produce a device at all,
// and waiting the full timeout to say "it did not appear" throws away the log line that says
// exactly why.
func ovpnOutWaitReady(procName, iface string, logMark int) error {
	deadline := time.Now().Add(ovpnOutUpTimeout)
	for {
		if ready, _ := ovpnOutIfaceReady(iface); ready {
			return nil
		}
		fresh := ovpnOutLogSince(procMgr.Logs(procName), logMark)
		if tell := ovpnOutLogTell(fresh); tell != "" {
			return fmt.Errorf("openvpn client did not come up: %s", tell)
		}
		if time.Now().After(deadline) {
			last := ovpnOutLastLines(fresh, 5)
			if last == "" {
				last = "no output from the client"
			}
			// The stage the connect reached is the whole answer here, and it is one the raw
			// tail cannot give: the last five lines of a connect that stalled after the
			// handshake are five SUCCESSFUL lines, so the operator is shown a certificate
			// verifying and told the panel timed out.
			if where := ovpnOutStalledAt(fresh); where != "" {
				return fmt.Errorf("openvpn client did not bring %s up within %s: %s. Last log:\n%s",
					iface, ovpnOutUpTimeout, where, last)
			}
			return fmt.Errorf("openvpn client did not bring %s up within %s. Last log:\n%s",
				iface, ovpnOutUpTimeout, last)
		}
		time.Sleep(ovpnOutPoll)
	}
}

// ovpnOutIfaceReady reports whether the device is usable, and its address.
func ovpnOutIfaceReady(iface string) (bool, string) {
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

// Down stops the client and clears up after it. Tolerates a tunnel that is already gone,
// which is what a panel restart between a failed Up and the next reconcile produces.
func (ovpnOutDriver) Down(cfg VpnOutboundConfig) error {
	iface := ovpnOutIfName(cfg.Tag)
	_ = procMgr.Stop(ovpnOutProcName(iface))

	// OpenVPN removes the device it created on the way out, so give it a moment before
	// forcing the issue; deleting a device out from under a still-exiting client is how you
	// get a name that comes back a second later with nothing behind it.
	for i := 0; i < 20; i++ {
		if _, err := netlink.LinkByName(iface); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if link, err := netlink.LinkByName(iface); err == nil {
		_ = netlink.LinkDel(link)
	}
	// The directory holds the credentials in clear and a copy of the private key, and Up
	// rewrites every byte of it, so there is nothing to keep and a real reason not to.
	_ = os.RemoveAll(ovpnOutDir(iface))
	return nil
}

// Status reports the two independent halves of "is this working": whether the supervised
// client is alive, and whether the kernel device it is supposed to have produced is actually
// there and configured. They come apart in practice, which is the point of reporting both: a
// crash-looping client is alive every five seconds and never has a device, and a client that
// lost its server keeps the device (persist-tun) while carrying nothing.
func (ovpnOutDriver) Status(cfg VpnOutboundConfig) (bool, string) {
	iface := ovpnOutIfName(cfg.Tag)
	name := ovpnOutProcName(iface)
	running := procMgr.IsRunning(name)
	ready, addr := ovpnOutIfaceReady(iface)

	var parts []string
	if running {
		parts = append(parts, "client running")
	} else {
		parts = append(parts, "CLIENT STOPPED")
	}
	if ready {
		parts = append(parts, iface+" up, address "+addr)
	} else if _, err := netlink.LinkByName(iface); err == nil {
		parts = append(parts, iface+" PRESENT BUT NOT CONFIGURED")
	} else {
		parts = append(parts, iface+" NOT PRESENT")
	}
	if link, err := netlink.LinkByName(iface); err == nil {
		if s := link.Attrs().Statistics; s != nil {
			parts = append(parts, fmt.Sprintf("rx %s, tx %s", ovpnOutBytes(s.RxBytes), ovpnOutBytes(s.TxBytes)))
		}
	}
	logs := procMgr.Logs(name)
	// A server can also PUSH compression, which Validate cannot see because it never reads
	// the server's reply. That failure is a single unrecognized-option line in a log nobody
	// reads, so it is translated here into the sentence that says what to do about it.
	if tell := ovpnOutLogTell(logs); tell != "" {
		parts = append(parts, tell)
	}
	detail := strings.Join(parts, ", ")
	if last := ovpnOutLastLines(logs, 5); last != "" {
		detail += "\n" + last
	}
	return running && ready, detail
}

// ---- log reading ----------------------------------------------------------------------------

// ovpnOutLogTell turns the handful of OpenVPN failures that are worth naming into one
// sentence. Everything else is left to the raw log lines Status appends: a wrong guess about
// what a log line means is worse than showing the line.
//
// Matched line by line rather than against the whole tail, because one of these tells has to
// distinguish two things that share a phrase. A healthy connect logs
// "Options error: option 'dhcp-option' cannot be used in this context ([PUSH-OPTIONS])"
// whenever the server pushes a resolver and the client is not taking pushed options, and a
// substring match over the blob read that as a broken config: on a working tunnel Status said
// the client had refused its own config, and, worse, the wait in Up would abort a perfectly
// good connect the moment that line appeared. A [PUSH-OPTIONS] complaint is about what the
// SERVER sent, so it is never a reason to condemn the local config.
//
// The last match wins, so what is reported is the most recent thing that went wrong rather
// than something the client has since recovered from.
func ovpnOutLogTell(log string) string {
	if log == "" {
		return ""
	}
	tell := ""
	for _, ln := range strings.Split(ovpnOutLastLines(log, 60), "\n") {
		pushed := strings.Contains(ln, "[PUSH-OPTIONS]")
		switch {
		case strings.Contains(ln, "AUTH_FAILED"):
			tell = "the server rejected the credentials (AUTH_FAILED)"
		case strings.Contains(ln, "No reply from server to push requests"):
			// OpenVPN's own line, after 64 seconds of asking. It only appears once the client
			// is PAST authentication, so it says something precise: the far side let this
			// account in and then never handed it a tunnel. On a server of this panel's own
			// kind that is the client-connect hook refusing, an exhausted address pool, or the
			// account's device limit being full -- none of which is a setting on this side.
			tell = "the server accepted the credentials and then never sent a configuration " +
				"(no PUSH_REPLY), so the tunnel has no address. That is the far side's to fix: " +
				"its connect hook, its address pool, or the device limit on that account"
		case strings.Contains(ln, "Unrecognized option") &&
			(strings.Contains(ln, "comp-lzo") || strings.Contains(ln, "compress")):
			// This one IS usually a pushed option, and it is fatal to the data path: the
			// server compresses and this build cannot decompress. The bundled binary has
			// both libraries, so reaching this means a host openvpn built without them.
			tell = "the server pushed compression, which this openvpn build does not have; " +
				"ask the provider to turn it off or install a distro openvpn that has it"
		// The four below are all "Options error" lines and must be matched BEFORE the
		// catch-all for that phrase, which would otherwise swallow them into "see the log".
		// Each names a shape the panel now accepts and only OpenVPN can refuse: since a
		// pasted profile is no longer pre-judged on its CA or its credentials, the sentence
		// an operator gets when one really is missing has to come from here.
		case strings.Contains(ln, "You must define CA file"):
			tell = "the profile has no CA to verify the server with (no `ca` line, no <ca> block and no " +
				"peer-fingerprint); paste the provider's CA certificate into the profile"
		case strings.Contains(ln, "No client-side authentication method is specified"):
			tell = "the profile gives the client nothing to authenticate WITH: it needs an inline " +
				"<cert>/<key> pair, a pkcs12, or auth-user-pass with a username and password filled in here"
		case strings.Contains(ln, "fails with") && strings.Contains(ln, "No such file"):
			tell = "the profile names a file that is not on this server (see the log line below). A .ovpn " +
				"that references ca.crt or ta.key by name needs those files pasted into it as inline " +
				"<ca>/<cert>/<key>/<tls-auth> blocks, since only the profile itself is copied to the server"
		case strings.Contains(ln, "specify only one of --tls-server, --tls-client, or --secret"):
			tell = "this profile mixes a static key with TLS: a `secret` config cannot also carry client, " +
				"tls-client or tls-server, and one of those is in the extra directives"
		case strings.Contains(ln, "allow-deprecated-insecure-static-crypto"):
			tell = "this openvpn refuses static-key (--secret) tunnels unless they are explicitly allowed. " +
				"Put `allow-deprecated-insecure-static-crypto` in the extra directives, or ask the provider " +
				"for a TLS profile"
		// The proxy refusing, before the TLS failure below, which is what this looks like
		// from a distance and is a different thing to go and check. The VPN server is not
		// the problem here: the client never got past the proxy standing in front of it.
		//
		// Both spellings, because they are two lines about one event and only the second
		// survives into a short tail: recv_socks_reply is logged once per attempt, and
		// SIGUSR1[soft,socks-error] is what the retry loop prints from then on.
		//
		// Measured against a SOCKS5 inbound with UDP turned off: the proxy answers the UDP
		// ASSOCIATE with an error and the client restarts on an ever-growing pause, forever,
		// with the tun never appearing. Naming UDP ASSOCIATE is the point of the sentence:
		// nothing else in the panel or the log connects "the tunnel will not come up" to
		// "this proxy only forwards TCP".
		case strings.Contains(ln, "recv_socks_reply") || strings.Contains(ln, "socks-error"):
			tell = "the SOCKS proxy refused to carry the connection to the VPN server. For a " +
				"`proto udp` profile that is almost always the proxy declining UDP ASSOCIATE, " +
				"which is how OpenVPN carries UDP over SOCKS5: allow UDP on the proxy, or use " +
				"the provider's TCP profile"
		case strings.Contains(ln, "Options error") && !pushed:
			tell = "the client refused its own config (Options error), see the log below"
		case strings.Contains(ln, "VERIFY ERROR") || strings.Contains(ln, "certificate verify failed"):
			tell = "the server certificate did not verify against the CA in this profile"
		case strings.Contains(ln, "Cannot allocate TUN/TAP dev"):
			tell = "the tun device could not be opened, check that the tun module is loaded"
		case strings.Contains(ln, "TLS Error: TLS key negotiation failed"):
			tell = "no usable reply from the server (wrong address, port or protocol, blocked, " +
				"or a tls-auth/tls-crypt key mismatch)"
		}
	}
	return tell
}

// ovpnOutStalledAt names how far a connect got before it stopped, for the case ovpnOutLogTell
// cannot answer: the one where nothing went wrong in any single line.
//
// This is the difference between a message an operator can act on and one that blames the
// panel. A client that reaches the far side, verifies its certificate and is then ignored logs
// nothing but success, so the timeout used to print five happy lines ending at "VERIFY OK" and
// the sentence "did not bring ovpnc-x up within 20s". Both halves are true and together they
// say the panel gave up, when what actually happened is that the far side stopped talking at a
// nameable point in the protocol.
//
// The stages are OpenVPN's own connect sequence, tested newest-first so what is reported is the
// furthest point reached. They come from the client's log verbatim (bundled 2.6.12):
//
//	Attempting to establish TCP connection with [AF_INET]...
//	TCP connection established with [AF_INET]...        (TCP only; UDP has only `link remote:`)
//	TLS: Initial packet from [AF_INET]..., sid=...
//	VERIFY OK: depth=0, ...
//	Control Channel: TLSv1.3, cipher ...                 <- the server ANSWERED the key exchange
//	[server] Peer Connection Initiated with [AF_INET]...
//	PUSH: Received control message: 'PUSH_REPLY,...'
//	Initialization Sequence Completed
//
// Deliberately NOT used by Status, and not consulted while the wait is still running: every
// stage below is a perfectly normal thing to be in the middle of for a second or two, and a
// classifier that fires early would condemn healthy connects exactly the way a substring match
// on the pushed-option warning once did. It is only meaningful because the wait has already
// expired, so it lives at the point where that is known.
func ovpnOutStalledAt(log string) string {
	if strings.TrimSpace(log) == "" {
		return ""
	}
	has := func(s string) bool { return strings.Contains(log, s) }
	switch {
	case has("Initialization Sequence Completed"):
		// The client thinks it finished, so this is not a stalled connect at all and the raw
		// tail is a better witness than a guess.
		return ""
	case has("PUSH: Received control message"):
		return "the server's PUSH_REPLY carried no address for the tunnel, so the device came up bare " +
			"(a server that expects its clients to bring their own `ifconfig` cannot be used as an outbound)"
	case has("Peer Connection Initiated"):
		return "the credentials were accepted and the server then never sent a configuration (no " +
			"PUSH_REPLY), so the tunnel never got an address. That is the far side's to fix: its connect " +
			"hook, its address pool, or the device limit on that account"
	case has("VERIFY OK") || has("VERIFY EKU OK"):
		// The user-visible failure this classifier was written for. Everything about it looks
		// healthy: the certificate chain verified, so the address, the port, the protocol and
		// the CA are all right, and the very next thing the client does is send the username
		// and password inside the key exchange. Being ignored at that exact point is the far
		// side's answer, and one specific far side gives it every time: an OpenVPN too old to
		// finish a key exchange over a TLS 1.3 control channel never replies, while the same
		// profile, credentials and binary get in immediately with `tls-version-max 1.2`.
		return "the server's certificate verified and the far side then went quiet: it never answered the " +
			"key exchange, which is the step that carries the username and password. Check them with the " +
			"provider -- and if the server is an old one, try `tls-version-max 1.2` in the extra directives, " +
			"since a server that cannot finish a TLS 1.3 control channel stops in exactly this place"
	case has("TLS: Initial packet from"):
		return "the TLS handshake with the server did not finish (the server replied but the two could not " +
			"agree, or its certificate chain never arrived)"
	case has("TCP connection established"):
		return "the server accepted the connection and then said nothing, so whatever is on that port did " +
			"not answer as an OpenVPN server (wrong port, something else listening on it, or a " +
			"tls-auth/tls-crypt key this profile does not carry, which makes a server ignore the client " +
			"in silence)"
	case has("Attempting to establish TCP connection"):
		return "the client never got a connection to the server (wrong address or port, or it is blocked " +
			"from this host)"
	case has("link remote:"):
		// UDP logs its remote before a single packet is sent, so "reached" would be a lie
		// here: this stage means nothing at all came back.
		return "nothing came back from the server (wrong address, port or protocol, blocked on the way, or " +
			"a tls-auth/tls-crypt key the server does not share, which makes it ignore the client in silence)"
	}
	return ""
}

// ovpnOutBytes renders a device counter. Deliberately a local copy rather than a shared
// helper: every driver is meant to be one self-contained file, and a formatting function is
// not worth a dependency between two protocols that otherwise have nothing to do with each
// other.
func ovpnOutBytes(n uint64) string {
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

// ovpnOutLastLines returns the final n lines of a log.
func ovpnOutLastLines(log string, n int) string {
	if log == "" {
		return ""
	}
	lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func ovpnOutLogLines(log string) int {
	if log == "" {
		return 0
	}
	return len(strings.Split(strings.TrimRight(log, "\n"), "\n"))
}

// ovpnOutLogSince returns the log from the given line onwards, i.e. the output of the current
// attempt only.
//
// The offset can drift if the ring buffer discarded lines in between (it holds 800), but it
// drifts in the safe direction: a discard makes this skip PAST some new lines, so at worst a
// tell is missed and the wait ends on its timeout, which still shows the tail. The opposite
// mistake, treating an older attempt's failure as this one's, is the one that matters, and it
// cannot happen.
func ovpnOutLogSince(log string, mark int) string {
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
