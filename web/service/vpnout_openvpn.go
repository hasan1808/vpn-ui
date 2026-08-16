package service

import (
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
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
	return []string{"profile", "password", "key", "tlsAuth", "tlsCrypt"}
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

func ovpnOutHasDirective(profile, name string) bool {
	for _, d := range ovpnOutDirectives(profile) {
		if d.name == name {
			return true
		}
	}
	return false
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
// inline blocks preserved verbatim. It also reports whether the profile asked for interactive
// credentials, which decides whether a username and password are mandatory.
func ovpnOutFilterProfile(profile string) (filtered string, needsAuth bool) {
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
		if name == "auth-user-pass" {
			needsAuth = true
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
	return b.String(), needsAuth
}

// ---- config generation --------------------------------------------------------------------

// ovpnOutBuildConfig renders the client config: the operator's profile (filtered) or the
// discrete fields, followed by the block this driver owns. The panel's block goes LAST so
// that for the single-valued options OpenVPN resolves by last-one-wins (dev, tun-mtu, verb)
// it is this driver's value that survives even if the filter missed one.
func ovpnOutBuildConfig(st *ovpnOutSettings, iface, dir string) (string, error) {
	var b strings.Builder
	b.WriteString("# Auto-generated by pro-ui (OpenVPN client outbound) - do not edit\n")

	needsAuth := false
	if strings.TrimSpace(st.Profile) != "" {
		var filtered string
		filtered, needsAuth = ovpnOutFilterProfile(st.Profile)
		b.WriteString(filtered)
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
		needsAuth = strings.TrimSpace(st.Username) != ""
	}

	b.WriteString("\n# ---- panel-owned settings, see vpnout_openvpn.go ----\n")
	b.WriteString("client\n")
	// Forced and deterministic, so Up/Down/Status know the device without parsing the log,
	// and so the synthesized freedom outbound can be bound to it the moment Up returns.
	b.WriteString("dev-type tun\n")
	b.WriteString(fmt.Sprintf("dev %s\n", iface))
	// The three route gates. See the file header; between them a pushed OR a locally written
	// redirect-gateway cannot reach the host routing table.
	b.WriteString("route-nopull\n")
	b.WriteString("route-noexec\n")
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
	if st.Mtu > 0 {
		b.WriteString(fmt.Sprintf("tun-mtu %d\n", st.Mtu))
		// An operator who sets an MTU knows something about the path that the server does
		// not, so the server's pushed value must not overwrite it.
		b.WriteString("pull-filter ignore \"tun-mtu\"\n")
	}
	if strings.TrimSpace(st.Username) != "" || strings.TrimSpace(st.Password) != "" {
		// A file, never the console: a bare auth-user-pass makes OpenVPN block on a terminal
		// that a supervised child process does not have, which shows up as a tunnel that
		// never connects and a log that stops after "Need username/password".
		b.WriteString(fmt.Sprintf("auth-user-pass %s\n", ovpnOutAuthPath(dir)))
	} else if needsAuth {
		return "", fmt.Errorf("this profile authenticates with a username and password, but none were given")
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
		if !ovpnOutHasDirective(profile, "remote") {
			return fmt.Errorf("this profile has no `remote` line, so there is no server to dial")
		}
		if ovpnOutHasDirective(profile, "auth-user-pass") &&
			strings.TrimSpace(st.Username) == "" && strings.TrimSpace(st.Password) == "" {
			return fmt.Errorf("this profile authenticates with a username and password, but none were given")
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
	name := ovpnOutProcName(iface)

	if ovpnOutUnchanged(dir, conf, auth) && procMgr.IsRunning(name) {
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
func ovpnOutUnchanged(dir, conf, auth string) bool {
	have, err := os.ReadFile(ovpnOutConfPath(dir))
	if err != nil || string(have) != conf {
		return false
	}
	haveAuth, err := os.ReadFile(ovpnOutAuthPath(dir))
	if err != nil {
		return auth == ""
	}
	return string(haveAuth) == auth
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
		case strings.Contains(ln, "Unrecognized option") &&
			(strings.Contains(ln, "comp-lzo") || strings.Contains(ln, "compress")):
			// This one IS usually a pushed option, and it is fatal to the data path: the
			// server compresses and this build cannot decompress. The bundled binary has
			// both libraries, so reaching this means a host openvpn built without them.
			tell = "the server pushed compression, which this openvpn build does not have; " +
				"ask the provider to turn it off or install a distro openvpn that has it"
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
