package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
)

// The certificate an ocserv inbound on another vpn-ui actually handed out before the
// generator learned to set a SAN: self-issued, CA:FALSE, CN a description rather than
// an address, no subjectAltName. Kept verbatim because the golden pin below was
// verified twice against it outside this package: once with
//
//	openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
//	  openssl dgst -sha256 -binary | openssl base64
//
// and once by the real openconnect client, which accepted this pin and carried traffic
// against the gateway that presented this certificate.
const ocSelfSignedLeafPEM = `-----BEGIN CERTIFICATE-----
MIIB0jCCAVigAwIBAgIIGMdVnc3GKrgwCgYIKoZIzj0EAwMwNTEPMA0GA1UEChMG
dnBuLXVpMSIwIAYDVQQDExl2cG4tdWkgT3BlbkNvbm5lY3QgU2VydmVyMB4XDTI2
MDczMTA5MjUxM1oXDTM2MDcyODA5MjUxM1owNTEPMA0GA1UEChMGdnBuLXVpMSIw
IAYDVQQDExl2cG4tdWkgT3BlbkNvbm5lY3QgU2VydmVyMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEGJpGB4aXmKDWeFIBNZ7y4gqnLYWpfBUtrc2fLuylcwvS/k+3oL5f
67i1cYPaujloOjNUTKubudHg7K0j8PNS8nFOHmSoJA6AUE2Fe7iVE+yCa1OOGapD
wrGu0SS4QGC+ozUwMzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUH
AwEwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAwNoADBlAjEAqCRzmavOswl6DO1R
X0O6U4mkBNjd7/ljL7hly9oD6HqUEK5KDTFl1uB9yDFU5wWHAjBI58xUSHuxSXOY
iFtNdWaqoEAshIDNAPTnb82Vmj88zbDDx5HnmY3/Lf8RtSmqFU0=
-----END CERTIFICATE-----`

const ocSelfSignedLeafPin = "pin-sha256:CYZgLyqRswvjrcEay0B5opi2Y8Jw6nSvgOBUIU1IJ24="

func mkCert(t *testing.T, isCA bool, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A self-signed gateway certificate pasted into the CA box is pinned, which is the
// only thing that can authenticate it: it is not a CA, so it cannot anchor a chain.
func TestOcOutPinSelfSigned(t *testing.T) {
	if got := ocOutPinSelfSigned(ocSelfSignedLeafPEM); got != ocSelfSignedLeafPin {
		t.Fatalf("self-signed leaf: got %q, want %q", got, ocSelfSignedLeafPin)
	}
	if got := ocOutPinSelfSigned("\n\n  " + ocSelfSignedLeafPEM + "\n"); got != ocSelfSignedLeafPin {
		t.Fatalf("surrounding whitespace changed the pin: %q", got)
	}
}

// A real CA must keep being used as a CA. Pinning its key would reject the gateway,
// whose leaf this side has never seen.
func TestOcOutPinSelfSignedLeavesACAAlone(t *testing.T) {
	if got := ocOutPinSelfSigned(mkCert(t, true, "some private CA")); got != "" {
		t.Fatalf("CA certificate was pinned: %q", got)
	}
}

func TestOcOutPinSelfSignedIgnoresBundlesAndJunk(t *testing.T) {
	bundle := mkCert(t, false, "leaf") + mkCert(t, true, "issuer")
	if got := ocOutPinSelfSigned(bundle); got != "" {
		t.Fatalf("a two-certificate bundle was pinned: %q", got)
	}
	for _, junk := range []string{"", "   ", "not a pem", "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"} {
		if got := ocOutPinSelfSigned(junk); got != "" {
			t.Fatalf("junk %q produced a pin: %q", junk, got)
		}
	}
}

// The generator must name the gateway. A certificate with no subjectAltName cannot be
// verified by name by anything, which is what made a self-signed ocserv/SSTP inbound
// unreachable from any client that checks, this panel's own outbound included.
func TestSelfSignedServerCertsCarrySANs(t *testing.T) {
	for _, tc := range []struct {
		name string
		gen  func(string) (string, string, error)
	}{
		{"ocserv", (&OcservService{}).GenerateSelfSignedCert},
		{"sstp", (&SstpService{}).GenerateSelfSignedCert},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, _, err := tc.gen("203.0.113.7")
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				t.Fatal("no PEM block")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if cert.Subject.CommonName != "203.0.113.7" {
				t.Errorf("CN = %q, want the server address", cert.Subject.CommonName)
			}
			if err := cert.VerifyHostname("203.0.113.7"); err != nil {
				t.Errorf("the address it was minted for does not verify: %v", err)
			}
			var haveIP bool
			for _, ip := range cert.IPAddresses {
				if ip.Equal(net.ParseIP("203.0.113.7")) {
					haveIP = true
				}
			}
			if !haveIP {
				t.Errorf("no iPAddress SAN, got %v", cert.IPAddresses)
			}
			// Both forms: several real clients read an address out of dNSName.
			if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "203.0.113.7" {
				t.Errorf("dNSName SANs = %v, want [203.0.113.7]", cert.DNSNames)
			}
			// And it is still a leaf, so the outbound's paste-the-cert path pins it.
			if got := ocOutPinSelfSigned(certPEM); !strings.HasPrefix(got, "pin-sha256:") {
				t.Errorf("freshly generated cert is not pinnable: %q", got)
			}
		})
	}
}

// ---- dialling the gateway through a proxy -----------------------------------------
//
// The mechanism of last resort, and for a tunnel whose carrier is an ordinary Xray
// outbound the ONLY one: such an outbound owns no netdev, so nothing can be chained to
// it by routing and the VPN client's own proxy support has to do the work.
//
// Everything asserted here was measured against the bundled clients before it was
// written. openconnect v9.21: socks4:// is refused at startup ("Only http or socks(5)
// proxies supported"), a URL with no scheme is taken as http, userinfo is
// percent-DECODED on the way in (`bo%40b:s%3Acr3t@` arrived at the proxy as
// `bo@b:s:cr3t`), and HTTP Basic to a proxy is disabled unless proxy-auth asks for it.
// sstp-client 1.0.20: it never looks at the scheme, and answered a socks5:// URL by
// writing `CONNECT vpn.invalid:443 HTTP/1.1` at the SOCKS port.

const ocProxyTestIface = "occ-vpn1"

// ocProxyConf renders the config file's text the way the driver does, minus the write.
// The temp dir carries no PEMs, so the certificate branches stay out of the way.
func ocProxyConf(t *testing.T, s *ocOutSettings) string {
	t.Helper()
	return ocOutRenderConfig(t.TempDir(), ocProxyTestIface, s)
}

// The generated directives, which are the whole feature: openconnect takes one URL and
// everything about the proxy has to survive being folded into it.
func TestOcOutProxyConfig(t *testing.T) {
	base := ocOutSettings{Server: "vpn.example.com", Username: "u", Password: "p"}
	with := func(f func(*ocOutSettings)) ocOutSettings {
		s := base
		f(&s)
		return s
	}
	for _, tc := range []struct {
		name    string
		st      ocOutSettings
		want    []string
		notWant []string
	}{
		{
			// The default, and the state of every tunnel that already exists. `proxy`
			// with no argument is a config error, so nothing may be written at all.
			name:    "no proxy writes no directive",
			st:      base,
			notWant: []string{"proxy-auth digest,ntlm,basic"},
		},
		{
			// A blank scheme box means socks5, and a blank port means 1080 rather than
			// openconnect's own fallback of 80, which is never a SOCKS port.
			name: "a bare host is socks5 on 1080",
			st:   with(func(s *ocOutSettings) { s.Proxy = "10.0.0.9" }),
			want: []string{"proxy socks5://10.0.0.9:1080"},
		},
		{
			name: "an explicit socks5 port",
			st: with(func(s *ocOutSettings) {
				s.ProxyType, s.Proxy, s.ProxyPort = "socks5", "127.0.0.1", 10808
			}),
			want:    []string{"proxy socks5://127.0.0.1:10808"},
			notWant: []string{"proxy-auth digest,ntlm,basic"},
		},
		{
			// http is the other half of the choice, and its blank port is 8080: the
			// client's own default of 80 is a web port, not a proxy port.
			name: "an http proxy takes 8080",
			st: with(func(s *ocOutSettings) {
				s.ProxyType, s.Proxy = "http", "proxy.example.net"
			}),
			want: []string{"proxy http://proxy.example.net:8080"},
		},
		{
			// SOCKS5 carries username/password in its own sub-negotiation, taken
			// straight from the URL, so nothing else is needed.
			name: "socks5 credentials go in the url and nowhere else",
			st: with(func(s *ocOutSettings) {
				s.Proxy, s.ProxyPort, s.ProxyUser, s.ProxyPass = "10.0.0.9", 1080, "pu", "pp"
			}),
			want:    []string{"proxy socks5://pu:pp@10.0.0.9:1080"},
			notWant: []string{"proxy-auth digest,ntlm,basic"},
		},
		{
			// The line that is not guessable. Without proxy-auth, openconnect sends NO
			// Proxy-Authorization header at all and stops at "Proxy requested Basic
			// authentication which is disabled by default", so http credentials without
			// it are credentials that are never used.
			name: "http credentials need proxy-auth or they are never sent",
			st: with(func(s *ocOutSettings) {
				s.ProxyType, s.Proxy, s.ProxyPort = "http", "proxy.example.net", 3128
				s.ProxyUser, s.ProxyPass = "pu", "pp"
			}),
			want: []string{
				"proxy http://pu:pp@proxy.example.net:3128",
				"proxy-auth digest,ntlm,basic",
			},
		},
		{
			// openconnect percent-decodes both halves, so they have to be encoded on the
			// way in or a password containing @ : or % reaches the proxy as a different
			// password than the one that was typed.
			name: "credentials are percent-encoded into the userinfo",
			st: with(func(s *ocOutSettings) {
				s.ProxyType, s.Proxy, s.ProxyPort = "http", "10.0.0.9", 3128
				s.ProxyUser, s.ProxyPass = "bo@b", "s:cr3t/100%"
			}),
			want: []string{"proxy http://bo%40b:s%3Acr3t%2F100%25@10.0.0.9:3128"},
		},
		{
			// A username with no password is unusual but legal, and the colon must still
			// be there or the proxy reads the username as the whole userinfo.
			name: "a password-less username still writes a pair",
			st: with(func(s *ocOutSettings) {
				s.Proxy, s.ProxyPort, s.ProxyUser = "10.0.0.9", 1080, "pu"
			}),
			want: []string{"proxy socks5://pu:@10.0.0.9:1080"},
		},
		{
			// Not implied, and this is the guard on that decision: openconnect disables
			// the UDP data channel itself behind a proxy ("No DTLS when connected via
			// proxy"), so writing no-dtls would change nothing about the session and
			// would leave the form's own switch disagreeing with the config.
			name: "a proxy does not silently turn the DTLS switch off",
			st: with(func(s *ocOutSettings) {
				s.Proxy, s.ProxyPort = "10.0.0.9", 1080
			}),
			want:    []string{"proxy socks5://10.0.0.9:1080"},
			notWant: []string{"no-dtls"},
		},
		{
			name: "the DTLS switch is still the operator's to set",
			st: with(func(s *ocOutSettings) {
				s.Proxy, s.ProxyPort, s.NoDtls = "10.0.0.9", 1080, true
			}),
			want: []string{"proxy socks5://10.0.0.9:1080", "no-dtls"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			conf := ocProxyConf(t, &st)
			wantLines(t, conf, tc.want...)
			wantNoLines(t, conf, tc.notWant...)
			if st.Proxy == "" {
				for _, ln := range strings.Split(conf, "\n") {
					if strings.HasPrefix(strings.TrimSpace(ln), "proxy") {
						t.Errorf("a tunnel with no proxy carries %q:\n%s", ln, conf)
					}
				}
			}
		})
	}
}

// The upgrade guarantee, and the reason every proxy field carries omitempty.
//
// pppOutFingerprintOf hashes the MARSHALLED settings, and the hash is written into the
// generated config; Up returns early only when the two agree. So a new field that
// marshalled as `"proxy":""` would change the fingerprint of every OpenConnect tunnel
// that already exists, and the first reconcile after the upgrade would tear each one
// down and redial it for a setting nobody touched.
//
// The golden string is the JSON this struct produced BEFORE the proxy fields existed.
func TestOcOutProxylessSettingsMarshalUnchanged(t *testing.T) {
	const golden = `{"server":"vpn.example.com","protocol":"","username":"u","password":"p",` +
		`"authgroup":"","totpSecret":"","cert":"","key":"","keyPassword":"","caCert":"",` +
		`"serverCert":"","noDtls":false,"mtu":0}`
	s := ocOutSettings{Server: "vpn.example.com", Username: "u", Password: "p"}
	got, err := json.Marshal(&s)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != golden {
		t.Fatalf("a tunnel with no proxy no longer marshals the way it did, so every existing "+
			"OpenConnect outbound would redial on upgrade.\n got: %s\nwant: %s", got, golden)
	}
}

// The form's scheme box has a default and posts "socks5" whether or not a proxy is set,
// so a tunnel re-saved with nothing changed would otherwise fingerprint differently and
// redial. parse() drops the scheme and port when there is no host, which is what keeps
// that save a no-op.
func TestOcOutParseDropsAProxySchemeWithNoHost(t *testing.T) {
	d := &ocOutDriver{}
	posted := `{"server":"vpn.example.com","username":"u","password":"p",` +
		`"proxyType":"socks5","proxyPort":1080}`
	s, err := d.parse(VpnOutboundConfig{Tag: "vpn1", Settings: json.RawMessage(posted)})
	if err != nil {
		t.Fatal(err)
	}
	bare := ocOutSettings{Server: "vpn.example.com", Username: "u", Password: "p"}
	if pppOutFingerprintOf(s) != pppOutFingerprintOf(&bare) {
		t.Fatalf("re-saving a proxy-less tunnel changed its fingerprint, so it would redial: "+
			"%s vs %s", pppOutFingerprintOf(s), pppOutFingerprintOf(&bare))
	}
}

// The other half of the same mechanism: a proxy that CHANGES has to be noticed, or Up
// returns the live tunnel, the old proxy stays in use and the panel reports the save as
// successful.
func TestOcOutProxyChangesTheFingerprint(t *testing.T) {
	base := ocOutSettings{Server: "vpn.example.com", Username: "u", Password: "p"}
	proxied := base
	proxied.Proxy, proxied.ProxyPort = "10.0.0.9", 1080

	seen := map[string]string{pppOutFingerprintOf(&base): "no proxy"}
	for _, tc := range []struct {
		name string
		st   ocOutSettings
	}{
		{"proxy added", proxied},
		{"host changed", func() ocOutSettings { s := proxied; s.Proxy = "10.0.0.10"; return s }()},
		{"port changed", func() ocOutSettings { s := proxied; s.ProxyPort = 1081; return s }()},
		{"scheme changed", func() ocOutSettings { s := proxied; s.ProxyType = "http"; return s }()},
		{"username changed", func() ocOutSettings { s := proxied; s.ProxyUser = "pu"; return s }()},
		{"password changed", func() ocOutSettings {
			s := proxied
			s.ProxyUser, s.ProxyPass = "pu", "pp"
			return s
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			fp := pppOutFingerprintOf(&st)
			if prev, dup := seen[fp]; dup {
				t.Fatalf("%q fingerprints the same as %q, so changing it would leave the old "+
					"client running and report the save as saved", tc.name, prev)
			}
			seen[fp] = tc.name
			// And the fingerprint that is COMPARED is the one in the file, so it has to
			// travel with the config text.
			if !strings.Contains(ocProxyConf(t, &st), ocOutFingerprintMark+fp) {
				t.Fatalf("the config does not carry fingerprint %s", fp)
			}
		})
	}
}

// Shapes refused while the modal is still open, because each one fails at dial time as
// something that names the gateway rather than the proxy, 45 seconds later.
func TestOcOutValidateProxy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		st      ocOutSettings
		wantErr string
	}{
		{"nothing set", ocOutSettings{}, ""},
		{"host alone", ocOutSettings{Proxy: "10.0.0.9"}, ""},
		{"host, scheme, port and credentials", ocOutSettings{ProxyType: "http", Proxy: "10.0.0.9",
			ProxyPort: 3128, ProxyUser: "pu", ProxyPass: "pp"}, ""},
		{"credentials with no address", ocOutSettings{ProxyUser: "pu", ProxyPass: "pp"},
			"credentials but no address"},
		{"a password with no username", ocOutSettings{Proxy: "10.0.0.9", ProxyPass: "pp"},
			"no username with it"},
		{"host and port in one box", ocOutSettings{Proxy: "10.0.0.9 1080"}, "whitespace in it"},
		// A scheme typed into the host box would become socks5://http://host, which
		// openconnect resolves as a host called "http".
		{"a scheme in the host box", ocOutSettings{Proxy: "socks5://10.0.0.9"}, "carries a scheme"},
		// socks4 is the one an operator reaches for, and openconnect genuinely refuses
		// it: "Only http or socks(5) proxies supported", at startup.
		{"socks4", ocOutSettings{ProxyType: "socks4", Proxy: "10.0.0.9"}, "socks4 in particular"},
		{"an impossible port", ocOutSettings{Proxy: "10.0.0.9", ProxyPort: 70000}, "outside 0-65535"},
		{"a line break in the proxy password", ocOutSettings{Proxy: "10.0.0.9",
			ProxyUser: "pu", ProxyPass: "p\np"}, "cannot contain line breaks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			err := ocOutValidateProxy(&st)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("this shape must be accepted: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("this shape must be refused, got no error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("the refusal does not name the problem: %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// The proxy password must never reach the browser, for the same reason the gateway
// password does not: /vpnoutbound/list is what the outbound table is drawn from.
func TestOcOutProxyPasswordIsASecret(t *testing.T) {
	for _, k := range (&ocOutDriver{}).SecretKeys() {
		if k == "proxyPass" {
			return
		}
	}
	t.Fatal("proxyPass is not declared secret, so the proxy password would be echoed back " +
		"to every browser that lists the outbounds")
}

// A proxy failure has to be named as the PROXY's, because openconnect's own tail ends in
// "Failed to open HTTPS connection to <gateway>" whatever went wrong, and that sends the
// operator to the wrong machine.
func TestOcOutLogTellNamesTheProxy(t *testing.T) {
	for _, tc := range []struct{ name, log, want string }{
		{"a scheme the client refuses", "Only http or socks(5) proxies supported\n", "http and socks5 only"},
		{"a refused CONNECT", "Proxy CONNECT request failed: 403\n", "HTTP proxy refused"},
		{"basic disabled", "Proxy requested Basic authentication which is disabled by default\n",
			"proxy-auth"},
		{"a socks refusal", "SOCKS proxy error 02: connection not allowed\n", "SOCKS proxy refused"},
		{"socks wants credentials", "SOCKS server requested username/password but we have none\n",
			"proxy username and password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The gateway-side tail every one of these really ends with, so the test also
			// proves the proxy arms are reached before the generic ones.
			log := tc.log + "Failed to open HTTPS connection to vpn.example.com\n" +
				"Failed to complete authentication\n"
			if got := ocOutLogTell(log); !strings.Contains(got, tc.want) {
				t.Fatalf("log tell = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}

// ---- SSTP: the same field, and a client that only speaks one scheme ----------------

// The trap this refusal exists for. sstp-client does not look at the URL scheme at all:
// measured against the bundled 1.0.20, `socks5://127.0.0.1:<port>` made it open a plain
// TCP connection and write `CONNECT vpn.invalid:443 HTTP/1.1` at it. The proxy is up, the
// proxy is healthy, and the operator is told it could not be connected to.
func TestSstpOutProxyIsHttpOnly(t *testing.T) {
	for _, tc := range []struct{ name, proxy, wantErr string }{
		{"none", "", ""},
		{"http", "http://10.0.0.1:3128", ""},
		// Accepted because sstpc sends the identical CLEARTEXT CONNECT to it: https here
		// means only "the proxy is on 443", and refusing it would break a live tunnel.
		{"https", "https://proxy.example.net", ""},
		// No scheme is a working configuration too: sstpc falls back to port 80.
		{"no scheme", "10.0.0.1:3128", ""},
		{"socks5", "socks5://127.0.0.1:10808", "HTTP CONNECT proxies only"},
		{"socks5h", "socks5h://127.0.0.1:10808", "HTTP CONNECT proxies only"},
		{"socks4", "socks4://127.0.0.1:1080", "HTTP CONNECT proxies only"},
		{"something else entirely", "ftp://10.0.0.1", "not one the SSTP client understands"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sstpOutValidateProxy(tc.proxy)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("this proxy must be accepted: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("refusal = %v, want it to mention %q", err, tc.wantErr)
			}
			// And it has to be reached through the real entry point, or the modal never
			// sees it.
			cfg := VpnOutboundConfig{Tag: "vpn1", Kind: VpnOutSSTP, Settings: json.RawMessage(
				`{"server":"vpn.example.com","username":"u","password":"p","proxy":` +
					mustJSONString(t, tc.proxy) + `}`)}
			gotErr := (&sstpOutDriver{}).Validate(cfg)
			if (gotErr != nil) != (tc.wantErr != "") {
				t.Fatalf("Validate disagrees with sstpOutValidateProxy: %v", gotErr)
			}
		})
	}
}

// A SOCKS URL that made it into the database before the refusal existed must not be
// allowed to reach the client either, and the refusal names the proxy rather than
// leaving "Could not connect to proxy server" to be read as a dead proxy.
func TestSstpOutProxyReachesThePtyCommand(t *testing.T) {
	d := &sstpOutDriver{}
	s := &sstpOutSettings{Server: "vpn.example.com", Username: "u", Password: "p",
		Proxy: "http://pu:pp@10.0.0.1:3128"}
	got := d.ptyCommand("/usr/bin/sstpc", "vpn1", "/etc/vpn-ui-sstp-out/vpn1/ca.pem", s)
	if !strings.Contains(got, "--proxy 'http://pu:pp@10.0.0.1:3128'") {
		t.Fatalf("the proxy is not passed to sstpc: %s", got)
	}
	// Nothing else on that command line may carry a credential; the PPP password is
	// pppd's, out of a 0600 options file, and `ps` shows this string.
	if strings.Contains(got, "'p'") || strings.Contains(got, "--password") {
		t.Fatalf("the pty command line leaked the PPP password: %s", got)
	}

	bare := *s
	bare.Proxy = ""
	if strings.Contains(d.ptyCommand("/usr/bin/sstpc", "vpn1", "/etc/vpn-ui-sstp-out/vpn1/ca.pem", &bare), "--proxy") {
		t.Fatal("a tunnel with no proxy is given --proxy anyway")
	}
	// The idempotence key is a hash of the whole settings struct, so the proxy is
	// already inside it: changing it must not leave the old sstpc running while the
	// save reports success.
	if pppOutFingerprintOf(s) == pppOutFingerprintOf(&bare) {
		t.Fatal("adding a proxy did not change the fingerprint, so the old client would be kept")
	}
	other := *s
	other.Proxy = "http://pu:pp@10.0.0.2:3128"
	if pppOutFingerprintOf(s) == pppOutFingerprintOf(&other) {
		t.Fatal("changing the proxy host did not change the fingerprint")
	}
}

// The proxy's own failures, named as the proxy's. Without these they fall through to the
// arms below them, where "Connection refused" is reported as the SSTP SERVER refusing.
func TestSstpOutLogTellNamesTheProxy(t *testing.T) {
	for _, tc := range []struct{ name, log, want string }{
		{"proxy unreachable", "Could not connect to proxy server\n", "HTTP CONNECT proxy"},
		{"proxy wants credentials", "Proxy asked for credentials, none provided\n",
			"http://user:password@host:port"},
		{"unreadable url", "Could not parse the proxy URL\n", "http://host:port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// sstpc's real tail: the connect failure is followed by a generic socket
			// error that the arms further down would otherwise claim.
			log := "Unrecoverable socket error, 115\n" + tc.log + "Connection refused\n"
			if got := sstpOutLogTell(log); !strings.Contains(got, tc.want) {
				t.Fatalf("log tell = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A hostname is a dNSName only; there is no address to put in an iPAddress SAN.
func TestSelfSignedServerCertAcceptsAHostname(t *testing.T) {
	certPEM, _, err := (&OcservService{}).GenerateSelfSignedCert("vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("vpn.example.com"); err != nil {
		t.Errorf("hostname does not verify: %v", err)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("a hostname produced an iPAddress SAN: %v", cert.IPAddresses)
	}
}
