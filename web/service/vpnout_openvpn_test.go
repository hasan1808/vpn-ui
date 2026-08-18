package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What an operator imports is a .ovpn file somebody else wrote, and the panel's job is to
// run it, not to insist it be written the panel's way. These tests are therefore about the
// GENERATED CONFIG TEXT rather than about "no error": every one of the shapes below used to
// either be refused outright or be rendered into a config OpenVPN would not accept, and in
// both cases "it saved" would not have caught it.
//
// The device name and directory are the ones ovpnOutIfName/ovpnOutDir would produce for a
// tunnel tagged "vpn1", spelled out so the expectations read as the file they describe.
const (
	ovpnTestIface = "ovpnc-vpn1"
	ovpnTestDir   = "/etc/openvpn/out-ovpnc-vpn1"
)

func ovpnBuild(t *testing.T, st *ovpnOutSettings) string {
	t.Helper()
	conf, err := ovpnOutBuildConfig(st, ovpnTestIface, ovpnTestDir)
	if err != nil {
		t.Fatalf("ovpnOutBuildConfig: %v", err)
	}
	return conf
}

// hasLine reports whether the config carries a directive line exactly, ignoring the
// indentation and the trailing whitespace a pasted file arrives with. Line-exact rather
// than a substring search because "client" is a substring of half a dozen other
// directives, and `# ... client ...` comments are written into this config on purpose.
func hasLine(conf, want string) bool {
	for _, ln := range strings.Split(conf, "\n") {
		if strings.TrimSpace(ln) == want {
			return true
		}
	}
	return false
}

func wantLines(t *testing.T, conf string, lines ...string) {
	t.Helper()
	for _, want := range lines {
		if !hasLine(conf, want) {
			t.Errorf("the generated config is missing %q. Config:\n%s", want, conf)
		}
	}
}

func wantNoLines(t *testing.T, conf string, lines ...string) {
	t.Helper()
	for _, unwanted := range lines {
		if hasLine(conf, unwanted) {
			t.Errorf("the generated config carries %q and must not. Config:\n%s", unwanted, conf)
		}
	}
}

// The panel-owned block every TLS profile gets, whatever else is in it.
func wantPanelBlock(t *testing.T, conf string) {
	t.Helper()
	wantLines(t, conf,
		"client",
		"dev-type tun",
		"dev "+ovpnTestIface,
		"route-nopull",
		"route-noexec",
		`pull-filter ignore "redirect-gateway"`,
		"persist-tun",
		"script-security 1",
	)
}

// TestOvpnOutProfileShapes is the table the complaint came from: an .ovpn with no TLS
// settings, or with its keys inline, or with credentials of its own, has to be usable as
// imported.
func TestOvpnOutProfileShapes(t *testing.T) {
	// An absolute credentials file that really is on this box, for the one case where the
	// driver honours the profile's own auth-user-pass instead of writing its own.
	realAuth := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(realAuth, []byte("alice\nhunter2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		st   ovpnOutSettings
		// want/notWant are whole directive lines in the generated config.
		want    []string
		notWant []string
		// wantErr is a substring of the refusal, for the shapes that really cannot run.
		wantErr string
	}{
		{
			name: "inline ca/cert/key is passed through untouched",
			st: ovpnOutSettings{Profile: `client
dev tun
remote 203.0.113.10 1194 udp
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
CAFEBABE
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
CLIENTCERT
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
CLIENTKEY
-----END PRIVATE KEY-----
</key>
`},
			want: []string{
				"remote 203.0.113.10 1194 udp",
				"<ca>", "</ca>", "CAFEBABE",
				"<cert>", "</cert>", "CLIENTCERT",
				"<key>", "</key>", "CLIENTKEY",
				"remote-cert-tls server",
				// The profile's own `dev tun` is the panel's to decide, so it is commented
				// out rather than deleted.
				"# [vpn-ui] removed, owned by the panel: dev tun",
			},
			notWant: []string{"dev tun"},
		},
		{
			// The whole point of the complaint: no <ca>, no <cert>, no <key> anywhere. It
			// used to be impossible to even save one of these through the discrete fields'
			// CA rule; as a profile it must simply be written out as given.
			name: "a profile with no TLS material at all still renders",
			st: ovpnOutSettings{Profile: `remote 203.0.113.10 1194 udp
auth-user-pass
peer-fingerprint aa:bb:cc:dd
`, Username: "alice", Password: "hunter2"},
			want: []string{
				"remote 203.0.113.10 1194 udp",
				"peer-fingerprint aa:bb:cc:dd",
				"auth-user-pass " + ovpnTestDir + "/auth.txt",
			},
		},
		{
			name: "an inline tls-auth with no key-direction gets direction 1",
			st: ovpnOutSettings{Profile: `remote 203.0.113.10 1194 udp
<ca>
CA
</ca>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
0123456789abcdef
-----END OpenVPN Static key V1-----
</tls-auth>
`},
			want: []string{"<tls-auth>", "</tls-auth>", "key-direction 1"},
		},
		{
			// The profile said it already, so the panel must not say it a second time (and
			// must not contradict a provider who really did mean direction 0).
			name: "a profile with its own key-direction is left alone",
			st: ovpnOutSettings{Profile: `remote 203.0.113.10 1194 udp
key-direction 0
<tls-auth>
KEY
</tls-auth>
`},
			want:    []string{"key-direction 0"},
			notWant: []string{"key-direction 1"},
		},
		{
			name: "tls-crypt is not directional and gets no key-direction",
			st: ovpnOutSettings{Profile: `remote 203.0.113.10 1194 udp
<tls-crypt>
KEY
</tls-crypt>
`},
			want:    []string{"<tls-crypt>"},
			notWant: []string{"key-direction 1"},
		},
		{
			name:    "a bare auth-user-pass with nothing typed is refused, by name",
			st:      ovpnOutSettings{Profile: "remote 203.0.113.10 1194 udp\nauth-user-pass\n"},
			wantErr: "authenticates with a username and password",
		},
		{
			name: "a bare auth-user-pass with credentials typed points at the panel's file",
			st: ovpnOutSettings{
				Profile:  "remote 203.0.113.10 1194 udp\nauth-user-pass\n",
				Username: "alice", Password: "hunter2",
			},
			want: []string{
				"auth-user-pass " + ovpnTestDir + "/auth.txt",
				"# [vpn-ui] removed, owned by the panel: auth-user-pass",
			},
		},
		{
			// The shape that silently worked before only because the directive scanner
			// could not see it. It has to keep working, and for a reason now.
			name: "an inline auth-user-pass block carries its own credentials",
			st: ovpnOutSettings{Profile: `remote 203.0.113.10 1194 udp
<auth-user-pass>
alice
hunter2
</auth-user-pass>
`},
			want: []string{"<auth-user-pass>", "alice", "hunter2", "</auth-user-pass>"},
			// Nothing was typed, so the panel writes no auth.txt and must not name one.
			notWant: []string{"auth-user-pass " + ovpnTestDir + "/auth.txt"},
		},
		{
			// Relative to the process working directory, which is ovpnOutDir() and holds
			// only client.conf and auth.txt. Refused with the actual problem named, rather
			// than with the old "no credentials were given" (they may well have been, in a
			// file the panel cannot see).
			name:    "a relative auth-user-pass file is refused and named",
			st:      ovpnOutSettings{Profile: "remote 203.0.113.10 1194 udp\nauth-user-pass creds.txt\n"},
			wantErr: `"creds.txt"`,
		},
		{
			name:    "an absolute auth-user-pass file that is not there is refused too",
			st:      ovpnOutSettings{Profile: "remote 203.0.113.10 1194 udp\nauth-user-pass /etc/openvpn/nope.txt\n"},
			wantErr: "not a file on this server",
		},
		{
			name: "an absolute auth-user-pass file that exists is honoured verbatim",
			st:   ovpnOutSettings{Profile: "remote 203.0.113.10 1194 udp\nauth-user-pass " + realAuth + "\n"},
			want: []string{"auth-user-pass " + realAuth},
			notWant: []string{
				"auth-user-pass " + ovpnTestDir + "/auth.txt",
				"# [vpn-ui] removed, owned by the panel: auth-user-pass " + realAuth,
			},
		},
		{
			// Typed credentials win over the file: the panel wrote them for this tunnel and
			// knows its own file exists.
			name: "typed credentials override a usable auth-user-pass file",
			st: ovpnOutSettings{
				Profile:  "remote 203.0.113.10 1194 udp\nauth-user-pass " + realAuth + "\n",
				Username: "bob", Password: "s3cret",
			},
			want:    []string{"auth-user-pass " + ovpnTestDir + "/auth.txt"},
			notWant: []string{"auth-user-pass " + realAuth},
		},
		{
			name: "every remote line survives, in order",
			st: ovpnOutSettings{Profile: `client
remote 203.0.113.10 1194 udp
remote 203.0.113.11 1195 udp
remote 198.51.100.7 443 tcp
remote-random
`},
			want: []string{
				"remote 203.0.113.10 1194 udp",
				"remote 203.0.113.11 1195 udp",
				"remote 198.51.100.7 443 tcp",
				"remote-random",
			},
		},
		{
			name: "proto tcp is the profile's business, not the panel's",
			st: ovpnOutSettings{Profile: `remote 203.0.113.10 443 tcp
proto tcp-client
`},
			want: []string{"remote 203.0.113.10 443 tcp", "proto tcp-client"},
		},
		{
			// comp-lzo is checked against the binary's capabilities in Validate; it must not
			// be stripped, or a server that insists on it could never be talked to.
			name: "comp-lzo is kept",
			st: ovpnOutSettings{Profile: `remote 203.0.113.10 1194 udp
comp-lzo yes
`},
			want: []string{"comp-lzo yes"},
		},
		{
			name: "an operator MTU is forced and the pushed one filtered",
			st:   ovpnOutSettings{Profile: "remote 203.0.113.10 1194 udp\n", Mtu: 1380},
			want: []string{"tun-mtu 1380", `pull-filter ignore "tun-mtu"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			conf, err := ovpnOutBuildConfig(&st, ovpnTestIface, ovpnTestDir)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("this shape must be refused, got a config:\n%s", conf)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("the refusal does not name the problem: %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ovpnOutBuildConfig: %v", err)
			}
			wantPanelBlock(t, conf)
			wantLines(t, conf, tc.want...)
			wantNoLines(t, conf, tc.notWant...)
		})
	}
}

// A static-key profile has no TLS in it at all, and OpenVPN refuses `--client` beside
// `--secret` ("specify only one of --tls-server, --tls-client, or --secret"). The panel
// forced `client` unconditionally, so this shape could never run however correct the file
// was. Both spellings of a static key are covered because they reach the scanner by
// different routes: the directive is read as a directive, the inline block is one the
// directive scanner deliberately cannot see inside.
func TestOvpnOutStaticKeyProfile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
	}{
		{"the secret directive", `remote 203.0.113.10 1194 udp
secret /etc/openvpn/static.key
ifconfig 10.8.0.2 10.8.0.1
cipher AES-256-CBC
`},
		{"an inline secret block", `remote 203.0.113.10 1194 udp
<secret>
-----BEGIN OpenVPN Static key V1-----
0123456789abcdef
-----END OpenVPN Static key V1-----
</secret>
ifconfig 10.8.0.2 10.8.0.1
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := ovpnBuild(t, &ovpnOutSettings{Profile: tc.profile, Mtu: 1400})

			// The one line that made this shape impossible, and the pull-side directives
			// that mean nothing without it.
			wantNoLines(t, conf,
				"client",
				"pull",
				"route-nopull",
				`pull-filter ignore "redirect-gateway"`,
				`pull-filter ignore "route"`,
				`pull-filter ignore "dhcp-option"`,
				`pull-filter ignore "tun-mtu"`,
			)
			// What the tunnel still needs to be usable: a known device, no routing of its
			// own, and a supervised process that never blocks on a terminal.
			wantLines(t, conf,
				"dev-type tun",
				"dev "+ovpnTestIface,
				"route-noexec",
				"persist-tun",
				"nobind",
				"script-security 1",
				"verb 3",
				"tun-mtu 1400",
				"ifconfig 10.8.0.2 10.8.0.1",
			)
		})
	}
}

// ovpnPanelExportedProfile is a real .ovpn as this panel's own OpenVPN inbound exports one
// (OpenVpnService.GenerateClientConfig): username/password only, so a BARE auth-user-pass and
// no <cert>/<key> at all, the CA inline and nothing else, `proto tcp` rather than tcp-client,
// a `cipher`/`auth` pair, and two `setenv` lines that exist for OpenVPN Connect and are
// meaningless to the community client.
//
// It is here verbatim, CA and all, because it is the file an operator actually imports when
// they chain one of these panels behind another, and every clause of it has caught something:
// the bare auth-user-pass decides whether a credentials file is written at all, the missing
// <cert>/<key> is the shape an older Validate refused outright, `proto tcp` must survive
// untouched (the panel writes no proto of its own), and the inline <ca> must come out byte for
// byte or the server cannot be verified.
const ovpnPanelExportedProfile = `client
dev tun
proto tcp
remote x.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
setenv CLIENT_CERT 0
setenv opt data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-192-CBC:AES-128-CBC:DES-EDE3-CBC
cipher AES-256-CBC
auth SHA256
verb 3
<ca>
-----BEGIN CERTIFICATE-----
MIIByTCCAU6gAwIBAgIBATAKBggqhkjOPQQDAzAtMQ8wDQYDVQQKEwZ2cG4tdWkx
GjAYBgNVBAMTEXZwbi11aSBPcGVuVlBOIENBMB4XDTI2MDgxMTEzNDc0MFoXDTM2
MDgwODEzNDc0MFowLTEPMA0GA1UEChMGdnBuLXVpMRowGAYDVQQDExF2cG4tdWkg
T3BlblZQTiBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABBu9xclbMrRVu82feYLt
pQTWFAgFQJuUjq3huQoQuyFz45lBkZVvjcp2q1CCBePm1tIDpUF5k7+adTERdmUp
4NU0cu/46GcZAZge55HVGkjMbOTzcBNNf7x5LV2zrKXNA6NCMEAwDgYDVR0PAQH/
BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCD5HzuvKBrjC/gBWLOz
U0LwxCJ3MAoGCCqGSM49BAMDA2kAMGYCMQCRty1m4mB5JRppLW48VpSkYEE9FHgK
98OFWP2Bh00O+FRjXvpNwEqcUlD7iYmsklkCMQCVm/n2Puf1CdJZP7JQ9k5RTk9y
VnTzH6n3G6XivgNvT4tPi1ybGRFkYwtlCXUuT7I=
-----END CERTIFICATE-----
</ca>
`

// TestOvpnOutPanelExportedProfile pins the generated text for that file, in both of the two
// states it can be saved in. There is no third: this profile authenticates by username and
// password only, so either they were typed and the panel writes them, or they were not and the
// save must fail while the form is still open. A 20 second bring-up timeout is not an
// acceptable answer to a question that can be settled without dialling anything.
func TestOvpnOutPanelExportedProfile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		st      ovpnOutSettings
		want    []string
		notWant []string
		wantErr string
	}{
		{
			name: "with credentials it runs the profile as written and adds the panel's file",
			st: ovpnOutSettings{
				Profile:  ovpnPanelExportedProfile,
				Username: "32rctcg2", Password: "G96TbnWwz5",
			},
			want: []string{
				// The profile, verbatim apart from the two lines the panel owns.
				"client",
				"proto tcp",
				"remote x.com 1194",
				"remote-cert-tls server",
				"setenv CLIENT_CERT 0",
				"setenv opt data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-192-CBC:AES-128-CBC:DES-EDE3-CBC",
				"cipher AES-256-CBC",
				"auth SHA256",
				"<ca>", "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----", "</ca>",
				// The device is the panel's, so the profile's own `dev tun` is commented out
				// and the real name written in the panel block.
				"# [vpn-ui] removed, owned by the panel: dev tun",
				"dev " + ovpnTestIface,
				// A FILE, never the bare directive: a supervised child has no terminal to be
				// prompted on, and openvpn does not ask for the username until AFTER the TLS
				// handshake, so the bare form is a tunnel that verifies the server and then
				// hangs -- indistinguishable, in the log, from a far side that went quiet.
				"# [vpn-ui] removed, owned by the panel: auth-user-pass",
				"auth-user-pass " + ovpnTestDir + "/auth.txt",
			},
			notWant: []string{
				"dev tun",
				"auth-user-pass",   // the bare form, line-exact
				"proto tcp-client", // the panel writes no proto beside the profile's own
			},
		},
		{
			name:    "without credentials it is refused at save time, by name",
			st:      ovpnOutSettings{Profile: ovpnPanelExportedProfile},
			wantErr: "authenticates with a username and password, but none were given",
		},
		{
			name: "a username on its own is enough to write the file, and no password is not a bare directive",
			st: ovpnOutSettings{
				Profile:  ovpnPanelExportedProfile,
				Username: "32rctcg2",
			},
			want:    []string{"auth-user-pass " + ovpnTestDir + "/auth.txt"},
			notWant: []string{"auth-user-pass"},
		},
		{
			name: "the tls-version-max workaround for an old far side goes in through extra",
			st: ovpnOutSettings{
				Profile:  ovpnPanelExportedProfile,
				Username: "32rctcg2", Password: "G96TbnWwz5",
				Extra: "tls-version-max 1.2",
			},
			want: []string{"tls-version-max 1.2", "auth-user-pass " + ovpnTestDir + "/auth.txt"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			conf, err := ovpnOutBuildConfig(&st, ovpnTestIface, ovpnTestDir)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("this shape must be refused, got a config:\n%s", conf)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("the refusal does not name the problem: %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ovpnOutBuildConfig: %v", err)
			}
			wantPanelBlock(t, conf)
			wantLines(t, conf, tc.want...)
			wantNoLines(t, conf, tc.notWant...)
			// The credentials file is the other half of what Up writes, and an empty one is
			// worse than none: the far side gets a blank username and answers AUTH_FAILED.
			if auth := ovpnOutAuthContent(&st); strings.TrimSpace(auth) == "" {
				t.Errorf("the config names an auth file and ovpnOutAuthContent is empty: %q", auth)
			}
		})
	}
}

// The discrete fields are the other half of the form and must not have moved: an operator
// building a config by hand still gets `client`, the full pull-side block and the
// key-direction the inline tls-auth box cannot carry.
func TestOvpnOutDiscreteFieldsUnchanged(t *testing.T) {
	conf := ovpnBuild(t, &ovpnOutSettings{
		Server: "203.0.113.10", Port: 443, Proto: "tcp",
		Ca: "CACERT", Cert: "CLIENTCERT", Key: "CLIENTKEY", TlsAuth: "TAKEY",
		RemoteCertTls: true,
		Username:      "alice", Password: "hunter2",
	})
	wantPanelBlock(t, conf)
	wantLines(t, conf,
		"remote 203.0.113.10 443 tcp-client",
		"<ca>", "CACERT", "</ca>",
		"<tls-auth>", "TAKEY", "</tls-auth>",
		"key-direction 1",
		"remote-cert-tls server",
		"auth-user-pass "+ovpnTestDir+"/auth.txt",
	)
	// Exactly one, not one per reason.
	if n := strings.Count(conf, "\nkey-direction 1\n"); n != 1 {
		t.Errorf("key-direction 1 appears %d times, want 1. Config:\n%s", n, conf)
	}
}

// The scanner is what every decision above is made from, and three of its facts are
// invisible to ovpnOutDirectives by design (it never looks inside an inline block).
func TestOvpnOutScanProfile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
		want    ovpnOutProfileFacts
	}{
		{
			name:    "the bare interactive form",
			profile: "remote a 1 udp\nauth-user-pass\n",
			want:    ovpnOutProfileFacts{authDirective: true, hasRemote: true},
		},
		{
			name:    "the file form keeps its argument",
			profile: "remote a 1 udp\nauth-user-pass /etc/creds.txt\n",
			want:    ovpnOutProfileFacts{authDirective: true, authFile: "/etc/creds.txt", hasRemote: true},
		},
		{
			name:    "a quoted argument is unquoted",
			profile: "remote a 1 udp\nauth-user-pass \"/etc/creds.txt\"\n",
			want:    ovpnOutProfileFacts{authDirective: true, authFile: "/etc/creds.txt", hasRemote: true},
		},
		{
			name:    "an inline block is credentials, not a request for them",
			profile: "remote a 1 udp\n<auth-user-pass>\nalice\npw\n</auth-user-pass>\n",
			want:    ovpnOutProfileFacts{authInline: true, hasRemote: true},
		},
		{
			// The reason block bodies are skipped: base64 lines start with arbitrary words,
			// and "secret" or "remote" in a PEM body must not become a directive.
			name:    "a key body cannot forge a directive",
			profile: "<ca>\nsecretRemoteIfconfigKeyDirection\n</ca>\n",
			want:    ovpnOutProfileFacts{},
		},
		{
			name:    "commented-out lines say nothing",
			profile: "remote a 1 udp\n# secret /etc/k\n; ifconfig 1 2\n",
			want:    ovpnOutProfileFacts{hasRemote: true},
		},
		{
			name:    "a static key with its addresses",
			profile: "remote a 1 udp\nsecret /etc/k\nifconfig 10.8.0.2 10.8.0.1\n",
			want:    ovpnOutProfileFacts{staticKey: true, hasIfconfig: true, hasRemote: true},
		},
		{
			name:    "the long-form spelling of every directive",
			profile: "--remote a 1 udp\n--key-direction 1\n<tls-auth>\nk\n</tls-auth>\n",
			want:    ovpnOutProfileFacts{keyDirection: true, tlsAuthInline: true, hasRemote: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ovpnOutScanProfile(tc.profile); got != tc.want {
				t.Errorf("ovpnOutScanProfile() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Every check dropped from Validate has to come back as a sentence when OpenVPN itself
// refuses, or accepting more shapes just moves the failure somewhere nobody reads. The
// lines below are verbatim output from the bundled openvpn 2.6.12.
func TestOvpnOutLogTellNamesTheNewFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		log  string
		want string
	}{
		{
			name: "a profile with no CA",
			log:  "Options error: You must define CA file (--ca) or CA path (--capath) and/or peer fingerprint verification (--peer-fingerprint)\n",
			want: "no CA to verify the server",
		},
		{
			name: "a profile with nothing to authenticate with",
			log:  "Options error: No client-side authentication method is specified.  You must use either --cert/--key, --pkcs12, or --auth-user-pass\n",
			want: "nothing to authenticate WITH",
		},
		{
			name: "a profile that names a file it did not bring",
			log:  "Options error: --ca fails with 'ca.crt': No such file or directory (errno=2)\n",
			want: "names a file that is not on this server",
		},
		{
			name: "a static key next to a tls option",
			log:  "Options error: specify only one of --tls-server, --tls-client, or --secret\n",
			want: "mixes a static key with TLS",
		},
		{
			name: "an openvpn 2.7 that refuses static keys",
			log:  "Options error: DEPRECATION: No tls-client or tls-server option in configuration detected. OpenVPN 2.7 allows using this configuration when using --allow-deprecated-insecure-static-crypto but you should move to a proper configuration\n",
			want: "refuses static-key",
		},
		{
			// Past authentication and still no tunnel: the account got in and the server
			// then handed it nothing. Nothing on this side can fix that, and saying so is
			// the difference between the operator checking their password for an hour and
			// the operator talking to the provider.
			name: "the server let the client in and never pushed a configuration",
			log:  "No reply from server to push requests in 64s\n",
			want: "never sent a configuration",
		},
		{
			// The exact line the bundled 2.6.12 logs when the proxy declines UDP ASSOCIATE,
			// captured from a SOCKS5 inbound with udp turned off. Without this the operator
			// sees a tunnel that never comes up and a log full of restart pauses.
			name: "a socks proxy that will not carry udp",
			log: "TCP connection established with [AF_INET]127.0.0.1:31890\n" +
				"recv_socks_reply: Socks proxy returned bad reply\n",
			want: "UDP ASSOCIATE",
		},
		{
			// The retry loop's own line, which is all that is left in a short tail once the
			// client has been restarting for a while.
			name: "the socks retry loop",
			log:  "SIGUSR1[soft,socks-error] received, process restarting\n",
			want: "SOCKS proxy refused",
		},
		{
			// The generic catch-all still has to answer for everything else, and a
			// [PUSH-OPTIONS] complaint on a healthy tunnel still has to say nothing.
			name: "anything else is still the generic options error",
			log:  "Options error: option 'frobnicate' is unknown\n",
			want: "refused its own config",
		},
		{
			name: "a pushed dhcp-option on a healthy tunnel is not a failure",
			log:  "Options error: option 'dhcp-option' cannot be used in this context ([PUSH-OPTIONS])\n",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ovpnOutLogTell(tc.log)
			if tc.want == "" {
				if got != "" {
					t.Errorf("ovpnOutLogTell() = %q, want no tell at all", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("ovpnOutLogTell() = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}

// ovpnStalledLog is the client's own output, verbatim from the bundled 2.6.12, up to the
// stage named. Cut from a real capture against a real server, because the point of the
// classifier is that every one of these lines is a SUCCESS line: nothing in the text says
// anything went wrong, which is precisely why the log tail alone was useless.
var ovpnStalledLog = map[string]string{
	"dialling": `OpenVPN 2.6.12 x86_64-pc-linux-musl [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD]
Socket Buffers: R=[131072->131072] S=[16384->16384]
Attempting to establish TCP connection with [AF_INET]203.0.113.10:1194`,
	"connected": `Attempting to establish TCP connection with [AF_INET]203.0.113.10:1194
TCP connection established with [AF_INET]203.0.113.10:1194
TCPv4_CLIENT link local: (not bound)
TCPv4_CLIENT link remote: [AF_INET]203.0.113.10:1194`,
	// UDP names its remote before it has sent anything, so this stage is "nothing came back"
	// rather than "the server was reached", and it must not borrow the TCP sentence.
	"udpSilent": `OpenVPN 2.6.12 x86_64-pc-linux-musl [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD]
UDPv4 link local: (not bound)
UDPv4 link remote: [AF_INET]203.0.113.10:1194`,
	"tlsStarted": `TCP connection established with [AF_INET]203.0.113.10:1194
TCPv4_CLIENT link remote: [AF_INET]203.0.113.10:1194
TLS: Initial packet from [AF_INET]203.0.113.10:1194, sid=383f4e53 b2b1aa17`,
	// The failure this was written for: the far side verified, then said nothing at all.
	"verified": `TLS: Initial packet from [AF_INET]203.0.113.10:1194, sid=383f4e53 b2b1aa17
VERIFY OK: depth=1, O=vpn-ui, CN=vpn-ui OpenVPN CA
VERIFY KU OK
Validating certificate extended key usage
++ Certificate has EKU (str) TLS Web Server Authentication, expects TLS Web Server Authentication
VERIFY EKU OK
VERIFY OK: depth=0, O=vpn-ui, CN=vpn-ui OpenVPN Server`,
	"authenticated": `VERIFY OK: depth=0, O=vpn-ui, CN=vpn-ui OpenVPN Server
Control Channel: TLSv1.2, cipher TLSv1.2 ECDHE-ECDSA-AES256-GCM-SHA384, peer certificate: 384 bits ECsecp384r1
[vpn-ui OpenVPN Server] Peer Connection Initiated with [AF_INET]203.0.113.10:1194
SENT CONTROL [vpn-ui OpenVPN Server]: 'PUSH_REQUEST' (status=1)
SENT CONTROL [vpn-ui OpenVPN Server]: 'PUSH_REQUEST' (status=1)`,
	"pushed": `[vpn-ui OpenVPN Server] Peer Connection Initiated with [AF_INET]203.0.113.10:1194
SENT CONTROL [vpn-ui OpenVPN Server]: 'PUSH_REQUEST' (status=1)
PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,ping 10,ping-restart 120'
OPTIONS IMPORT: timers and/or timeouts modified`,
	"up": `PUSH: Received control message: 'PUSH_REPLY,ifconfig 10.8.0.6 255.255.255.0'
TUN/TAP device tun0 opened
Initialization Sequence Completed`,
}

// A tunnel that never comes up is the one failure an operator cannot debug from the panel, and
// for the whole class where no single line is an error the timeout used to say only that the
// panel had waited 20 seconds. Each stage below has a different cause and a different owner,
// so each has to be named.
func TestOvpnOutStalledAt(t *testing.T) {
	for _, tc := range []struct {
		stage string
		want  string
	}{
		{"dialling", "never got a connection"},
		{"connected", "accepted the connection and then said nothing"},
		{"udpSilent", "nothing came back from the server"},
		{"tlsStarted", "TLS handshake with the server did not finish"},
		{"verified", "never answered the key exchange"},
		{"authenticated", "never sent a configuration"},
		{"pushed", "carried no address for the tunnel"},
		// A client that says it finished is not stalled, whatever else is wrong; guessing
		// here would put a wrong sentence on a tunnel that is merely slow to settle.
		{"up", ""},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			got := ovpnOutStalledAt(ovpnStalledLog[tc.stage])
			if tc.want == "" {
				if got != "" {
					t.Errorf("ovpnOutStalledAt() = %q, want no verdict at all", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("ovpnOutStalledAt() = %q, want it to mention %q", got, tc.want)
			}
		})
	}
	if got := ovpnOutStalledAt(""); got != "" {
		t.Errorf("ovpnOutStalledAt(\"\") = %q, want nothing", got)
	}
	if got := ovpnOutStalledAt("   \n\n"); got != "" {
		t.Errorf("ovpnOutStalledAt(blank) = %q, want nothing", got)
	}
	// The stall after the handshake is the one an operator can do something about from here,
	// so the sentence has to carry the workaround as well as the diagnosis.
	if got := ovpnOutStalledAt(ovpnStalledLog["verified"]); !strings.Contains(got, "tls-version-max 1.2") {
		t.Errorf("the post-handshake stall does not name the workaround: %q", got)
	}
}

// `extra` is the one settings field that is both free text and NOT withheld from the browser
// (SecretKeys keeps profile/password/key/tlsAuth/tlsCrypt back, and cannot mask a substring of
// a string it does hand over). Pasting key material into it would therefore publish that key
// to every browser that lists the outbounds, so Validate refuses the shape outright. Pinned
// here because it is a security rule enforced by one substring search, and the field it
// guards is the one an operator is invited to type freely into.
func TestOvpnOutInlineSecretInExtra(t *testing.T) {
	for _, tc := range []struct{ extra, want string }{
		{"<key>\nMIIE...\n</key>", "key"},
		{"<tls-auth>\nKEY\n</tls-auth>", "tls-auth"},
		{"<tls-crypt>\nKEY\n</tls-crypt>", "tls-crypt"},
		// Named in full: "<tls-crypt>" is not a substring of "<tls-crypt-v2>", so the v2
		// spelling needs its own entry in the list and the message has to say which one.
		{"<tls-crypt-v2>\nKEY\n</tls-crypt-v2>", "tls-crypt-v2"},
		{"<secret>\nKEY\n</secret>", "secret"},
		{"<KEY>\nupper case is the same block\n</KEY>", "key"},
		// Certificates are public by design, so refusing them would be pedantry, and plain
		// directives are what the field is for.
		{"<ca>\nCERT\n</ca>", ""},
		{"<cert>\nCERT\n</cert>", ""},
		{"tls-version-max 1.2\nauth-nocache", ""},
		{"", ""},
	} {
		if got := ovpnOutInlineSecretIn(tc.extra); got != tc.want {
			t.Errorf("ovpnOutInlineSecretIn(%q) = %q, want %q", tc.extra, got, tc.want)
		}
	}
}

// The filter's own contract, which the rest of the file leans on: panel-owned directives
// are commented rather than deleted, block bodies are untouched, and auth-user-pass moves
// between the two only on the caller's say-so.
func TestOvpnOutFilterProfileKeepAuth(t *testing.T) {
	profile := "remote a 1 udp\nauth-user-pass /etc/creds.txt\nup /bin/evil\n"

	dropped := ovpnOutFilterProfile(profile, false)
	if !strings.Contains(dropped, "# [vpn-ui] removed, owned by the panel: auth-user-pass /etc/creds.txt") {
		t.Errorf("auth-user-pass was not commented out:\n%s", dropped)
	}
	kept := ovpnOutFilterProfile(profile, true)
	if !hasLine(kept, "auth-user-pass /etc/creds.txt") {
		t.Errorf("auth-user-pass was not kept:\n%s", kept)
	}
	// keepAuth is about ONE directive. The script hooks are dropped either way: a .ovpn is
	// a document from a third party and up/down name a program OpenVPN runs as root.
	for _, conf := range []string{dropped, kept} {
		if hasLine(conf, "up /bin/evil") {
			t.Errorf("a script directive survived the filter:\n%s", conf)
		}
	}
}

// ---- dialling the server through a SOCKS5 proxy -----------------------------------
//
// The feature an operator is reaching for when they put a sockopt dialerProxy on a VPN
// tunnel: keep the VPN's exit address, but reach the VPN server through a proxy.
// dialerProxy cannot do it (it replaces the tunnel rather than wrapping it, which is why
// the synthesis deletes it); wrapping the OUTER OpenVPN connection can, and OpenVPN has
// had the directive for it all along.
//
// Verified end to end against the bundled 2.6.12 and a real server before these tests
// were written: with `socks-proxy 127.0.0.1 10808` the client logs "TCP connection
// established with [AF_INET]127.0.0.1:10808" (outer hop, exit 212.8.240.13 NL) and the
// address the internet sees through the tun is still 65.109.217.240 (FI).
func TestOvpnOutSocksProxyConfig(t *testing.T) {
	const profile = "remote 203.0.113.10 1194 tcp\n<ca>\nx\n</ca>\n"
	for _, tc := range []struct {
		name    string
		st      ovpnOutSettings
		want    []string
		notWant []string
	}{
		{
			// No proxy is the default and every existing tunnel's state: the directive must
			// not appear at all, since `socks-proxy` with no argument is a config error.
			name:    "no proxy writes no directive",
			st:      ovpnOutSettings{Profile: profile, Username: "u", Password: "p"},
			notWant: []string{"socks-proxy-retry"},
		},
		{
			name: "host only takes OpenVPN's own default port",
			st: ovpnOutSettings{Profile: profile, Username: "u", Password: "p",
				SocksProxy: "127.0.0.1"},
			want: []string{"socks-proxy 127.0.0.1 1080", "socks-proxy-retry"},
		},
		{
			name: "host and port",
			st: ovpnOutSettings{Profile: profile, Username: "u", Password: "p",
				SocksProxy: "127.0.0.1", SocksProxyPort: 10808},
			want: []string{"socks-proxy 127.0.0.1 10808", "socks-proxy-retry"},
		},
		{
			// OpenVPN takes proxy credentials only as a PATH, so the third argument is a
			// file this driver writes beside client.conf, and it is a different file from
			// the VPN's own auth.txt: the two authenticate to different machines.
			name: "credentials name their own file",
			st: ovpnOutSettings{Profile: profile, Username: "u", Password: "p",
				SocksProxy: "proxy.example.net", SocksProxyPort: 1080,
				SocksProxyUser: "pu", SocksProxyPass: "pp"},
			want: []string{
				"socks-proxy proxy.example.net 1080 " + ovpnTestDir + "/socks-auth.txt",
				"auth-user-pass " + ovpnTestDir + "/auth.txt",
			},
		},
		{
			// A password with no username writes no file (Validate refuses that shape), so
			// the directive must not name one either: OpenVPN would die on a missing file.
			name: "a username-less proxy names no credentials file",
			st: ovpnOutSettings{Profile: profile, Username: "u", Password: "p",
				SocksProxy: "127.0.0.1", SocksProxyPort: 1080, SocksProxyPass: "pp"},
			want:    []string{"socks-proxy 127.0.0.1 1080"},
			notWant: []string{"socks-proxy 127.0.0.1 1080 " + ovpnTestDir + "/socks-auth.txt"},
		},
		{
			// UDP is NOT refused. OpenVPN carries it over SOCKS5 with UDP ASSOCIATE, and
			// the bundled build does: measured against a real server, "SOCKS proxy wants us
			// to send UDP to 127.0.0.1:47536" then "Initialization Sequence Completed".
			// Refusing the pair would break the udp half of every provider that ships both.
			name: "a udp profile is proxied like any other",
			st: ovpnOutSettings{Profile: "remote 203.0.113.10 1194 udp\n<ca>\nx\n</ca>\n",
				Username: "u", Password: "p", SocksProxy: "127.0.0.1", SocksProxyPort: 10808},
			want: []string{"remote 203.0.113.10 1194 udp", "socks-proxy 127.0.0.1 10808"},
		},
		{
			// The profile's own proxy is left in place rather than filtered, and the panel's
			// line goes after it. Verified against the bundled 2.6.12: two socks-proxy lines
			// parse and the LAST one is dialled, so the panel's field wins without the
			// filter having to be exhaustive.
			name: "the panel's proxy is written after the profile's",
			st: ovpnOutSettings{Profile: "remote 203.0.113.10 1194 tcp\nsocks-proxy 10.0.0.9 1080\n",
				Username: "u", Password: "p", SocksProxy: "127.0.0.1", SocksProxyPort: 10808},
			want: []string{"socks-proxy 10.0.0.9 1080", "socks-proxy 127.0.0.1 10808"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			conf := ovpnBuild(t, &st)
			wantLines(t, conf, tc.want...)
			wantNoLines(t, conf, tc.notWant...)
			if tc.st.SocksProxy == "" {
				for _, ln := range strings.Split(conf, "\n") {
					if strings.HasPrefix(strings.TrimSpace(ln), "socks-proxy") {
						t.Errorf("a tunnel with no proxy carries %q:\n%s", ln, conf)
					}
				}
			}
		})
	}
}

// The order matters and is easy to get wrong by writing the directive into the profile
// section: OpenVPN resolves a repeated socks-proxy last-one-wins, so the panel's line has
// to come after the pasted one to be the one that is used.
func TestOvpnOutSocksProxyWinsOverTheProfiles(t *testing.T) {
	st := ovpnOutSettings{
		Profile:    "remote 203.0.113.10 1194 tcp\nsocks-proxy 10.0.0.9 1080\n",
		Username:   "u",
		Password:   "p",
		SocksProxy: "127.0.0.1", SocksProxyPort: 10808,
	}
	conf := ovpnBuild(t, &st)
	theirs := strings.Index(conf, "socks-proxy 10.0.0.9 1080")
	ours := strings.Index(conf, "socks-proxy 127.0.0.1 10808")
	if theirs < 0 || ours < 0 {
		t.Fatalf("both socks-proxy lines should be present:\n%s", conf)
	}
	if ours < theirs {
		t.Fatalf("the panel's socks-proxy is written BEFORE the profile's, so the profile's "+
			"is the one OpenVPN would dial:\n%s", conf)
	}
}

// The credentials file, which is the half of the feature that does not show up in the
// generated config text.
func TestOvpnOutSocksAuthContent(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   ovpnOutSettings
		want string
	}{
		{"no proxy", ovpnOutSettings{SocksProxyUser: "pu", SocksProxyPass: "pp"}, ""},
		{"no username", ovpnOutSettings{SocksProxy: "127.0.0.1", SocksProxyPass: "pp"}, ""},
		{"both", ovpnOutSettings{SocksProxy: "127.0.0.1", SocksProxyUser: "pu", SocksProxyPass: "pp"}, "pu\npp\n"},
		// A proxy that authenticates on the username alone is unusual but legal, and the
		// file still has to be two lines or OpenVPN reads past the end of it.
		{"username only", ovpnOutSettings{SocksProxy: "127.0.0.1", SocksProxyUser: "pu"}, "pu\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			if got := ovpnOutSocksAuthContent(&st); got != tc.want {
				t.Fatalf("socks auth file = %q, want %q", got, tc.want)
			}
		})
	}
}

// Half-filled shapes are refused while the modal is still open, because each of them
// fails at connect time as a generic SOCKS error that names nothing.
func TestOvpnOutValidateSocks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		st      ovpnOutSettings
		wantErr string
	}{
		{"nothing set", ovpnOutSettings{}, ""},
		{"host and port", ovpnOutSettings{SocksProxy: "127.0.0.1", SocksProxyPort: 10808}, ""},
		{"host, port and credentials", ovpnOutSettings{SocksProxy: "127.0.0.1", SocksProxyPort: 1080,
			SocksProxyUser: "pu", SocksProxyPass: "pp"}, ""},
		// A udp tunnel through a proxy is a supported combination, so nothing here may
		// refuse it. This case is the guard on that decision.
		{"udp with a proxy", ovpnOutSettings{Proto: "udp", SocksProxy: "127.0.0.1", SocksProxyPort: 1080}, ""},
		{"credentials with no address", ovpnOutSettings{SocksProxyUser: "pu", SocksProxyPass: "pp"},
			"credentials but no address"},
		{"a password with no username", ovpnOutSettings{SocksProxy: "127.0.0.1", SocksProxyPass: "pp"},
			"no username with it"},
		{"host and port in one box", ovpnOutSettings{SocksProxy: "127.0.0.1 10808"}, "whitespace in it"},
		{"an impossible port", ovpnOutSettings{SocksProxy: "127.0.0.1", SocksProxyPort: 70000},
			"outside 0-65535"},
		{"a line break in the proxy password", ovpnOutSettings{SocksProxy: "127.0.0.1",
			SocksProxyUser: "pu", SocksProxyPass: "p\np"}, "cannot contain line breaks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			err := ovpnOutValidateSocks(&st)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("this shape must be accepted: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("this shape must be refused, got no error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("the refusal does not name the problem: %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// The proxy password must never reach the browser, for the same reason the VPN password
// does not: /vpnoutbound/list is what the outbound table is drawn from.
func TestOvpnOutSocksPasswordIsASecret(t *testing.T) {
	for _, k := range ovpnOutDriver.SecretKeys(ovpnOutDriver{}) {
		if k == "socksProxyPass" {
			return
		}
	}
	t.Fatal("socksProxyPass is not declared secret, so the SOCKS proxy password would be " +
		"echoed back to every browser that lists the outbounds")
}
