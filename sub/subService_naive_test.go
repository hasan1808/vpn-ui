package sub

import (
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// These lock genNaiveLink to Inbound.genNaiveLink in web/assets/js/model/inbound.js
// byte for byte. Every share link is generated twice, once in Go for the subscription
// and once in the browser for the copy button and the QR, and the same account must get
// the same bytes from both (see the xhttp parity work, and TestGenMtprotoLinkParity).
//
// The strings below were produced by running the SHIPPED inbound.js under Node against
// the same rows, not by reading it: the two generators have diverged before on details
// nobody can spot by eye (Go sorts query keys, escapes userinfo through url.User, and
// HTML-escapes where the browser does not).
//
// remarkModel "-i" keeps the fragment to the inbound remark, which is what the browser
// caller passes genNaiveLink directly; genRemark's own e/o parts are tested elsewhere.

func naiveInbound(port int, clientJSON, network, sni string) *model.Inbound {
	tls := `{"serverName":"` + sni + `"}`
	if sni == "" {
		tls = `{}`
	}
	return &model.Inbound{
		Id: 1, Port: port, Protocol: model.NAIVE, Remark: "n",
		Settings:       `{"clients":[` + clientJSON + `],"network":"` + network + `"}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":` + tls + `}`,
	}
}

func TestGenNaiveLinkParity(t *testing.T) {
	s := &SubService{address: "vpn.example.com", remarkModel: "-i"}

	cases := []struct {
		name    string
		inbound *model.Inbound
		email   string
		want    string
	}{
		{
			// The account's own username is the Basic username, NOT its email.
			name:    "username set",
			inbound: naiveInbound(443, `{"email":"alice","username":"bob","password":"pw1"}`, "tcp", "n.example.com"),
			email:   "alice",
			want:    "naive+https://bob:pw1@vpn.example.com:443?sni=n.example.com#n",
		},
		{
			// The back-compat case: an account stored before the username field existed
			// authenticates with its email, and its link has to say so. The '@' must be
			// escaped or the authority holds two of them and a client dials the wrong host.
			name:    "no username falls back to the email",
			inbound: naiveInbound(443, `{"email":"alice@example.com","password":"p@ss:w/rd?x#y"}`, "tcp", "n.example.com"),
			email:   "alice@example.com",
			want:    "naive+https://alice%40example.com:p%40ss%3Aw%2Frd%3Fx%23y@vpn.example.com:443?sni=n.example.com#n",
		},
		{
			// An explicitly empty username is the same thing as an absent one. The JS
			// writes `username: ''` for every account the operator leaves blank, so this
			// is the shape most rows will actually have.
			name:    "empty username falls back to the email",
			inbound: naiveInbound(8443, `{"email":"carol","username":"","password":"pw3"}`, "udp", "q.example.com"),
			email:   "carol",
			want:    "naive+quic://carol:pw3@vpn.example.com:8443?sni=q.example.com#n",
		},
		{
			// network=udp is the only case that advertises quic; "tcp,udp" advertises
			// https, which every naive client speaks.
			name:    "both transports advertise https",
			inbound: naiveInbound(2096, `{"email":"dave","username":"dave-login","password":"pw4"}`, "tcp,udp", "d.example.com"),
			email:   "dave",
			want:    "naive+https://dave-login:pw4@vpn.example.com:2096?sni=d.example.com#n",
		},
		{
			name:    "no sni emits no query at all",
			inbound: naiveInbound(9443, `{"email":"erin","username":"erin-login","password":"pw5"}`, "udp", ""),
			email:   "erin",
			want:    "naive+quic://erin-login:pw5@vpn.example.com:9443#n",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := s.genNaiveLink(c.inbound, c.email); got != c.want {
				t.Fatalf("naive link mismatch:\n got=%q\nwant=%q", got, c.want)
			}
		})
	}
}

// The userinfo must ALWAYS be two colon-separated tokens, even when the account has no
// username of its own and the two halves would be the email and the password.
//
// This is not tidiness. v2rayN (NaiveFmt.cs, 7.24.4) URL-decodes the whole userinfo and
// only then splits it on the first colon; a userinfo with no colon is read as a password
// with an EMPTY username, which drops sing-box's `username` field and fails
// authentication with nothing on screen to explain it. So a link is never shortened to a
// single token, and a password containing a colon must arrive as %3A or v2rayN splits
// the credential in the middle of the password.
func TestGenNaiveLinkAlwaysEmitsTwoUserinfoTokens(t *testing.T) {
	s := &SubService{address: "vpn.example.com", remarkModel: "-i"}

	for _, c := range []struct {
		name    string
		inbound *model.Inbound
		email   string
	}{
		{"no username", naiveInbound(443, `{"email":"alice","password":"pw"}`, "tcp", ""), "alice"},
		{"empty username", naiveInbound(443, `{"email":"alice","username":"","password":"pw"}`, "tcp", ""), "alice"},
		{"username set", naiveInbound(443, `{"email":"alice","username":"bob","password":"pw"}`, "tcp", ""), "alice"},
	} {
		t.Run(c.name, func(t *testing.T) {
			link := s.genNaiveLink(c.inbound, c.email)
			authority := link[strings.Index(link, "://")+3:]
			if i := strings.IndexAny(authority, "/?#"); i >= 0 {
				authority = authority[:i]
			}
			userinfo := authority[:strings.LastIndex(authority, "@")]
			user, pass, found := strings.Cut(userinfo, ":")
			if !found {
				t.Fatalf("userinfo %q has no colon, so v2rayN reads it as a bare password: %s", userinfo, link)
			}
			if user == "" || pass == "" {
				t.Fatalf("userinfo %q has an empty half: %s", userinfo, link)
			}
		})
	}

	// A colon inside the PASSWORD must be escaped, or the split above lands inside it.
	link := s.genNaiveLink(naiveInbound(443, `{"email":"alice","username":"bob","password":"a:b"}`, "tcp", ""), "alice")
	if !strings.Contains(link, "bob:a%3Ab@") {
		t.Fatalf("a colon in the password must be percent-encoded: %s", link)
	}
}

// The username is looked up on the account addressed by EMAIL, because the email is
// still the accounting identity: the subscription, the traffic row and the quota all
// key on it. Getting this backwards would hand one subscriber another's credential.
func TestGenNaiveLinkPicksTheRequestedAccountsUsername(t *testing.T) {
	s := &SubService{address: "vpn.example.com", remarkModel: "-i"}
	in := &model.Inbound{
		Id: 1, Port: 443, Protocol: model.NAIVE, Remark: "n",
		Settings: `{"clients":[` +
			`{"email":"alice","username":"alice-login","password":"pw-a"},` +
			`{"email":"bob","username":"bob-login","password":"pw-b"}` +
			`],"network":"tcp"}`,
		StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{}}`,
	}
	if got, want := s.genNaiveLink(in, "bob"), "naive+https://bob-login:pw-b@vpn.example.com:443#n"; got != want {
		t.Fatalf("wrong account:\n got=%q\nwant=%q", got, want)
	}
}
