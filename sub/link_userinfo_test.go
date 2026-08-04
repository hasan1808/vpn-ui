package sub

import (
	"net/url"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// A credential carrying an "@" is the one input that silently breaks a share link.
// A naive account with no username of its own authenticates with its EMAIL, so every
// such account with a real address hits this: unescaped, the authority has two "@" and
// a client splits it at the wrong one, dialling a host that is not the server. The link
// still looks plausible.
//
// Go escapes userinfo through url.User/url.UserPassword and the browser through
// Inbound.encodeUserinfo(); the two agree, but neither is obvious from reading, so the
// property is pinned here rather than assumed. Asserted by round-trip (the parsed
// credential must equal the original and the host must be untouched) because that
// holds whatever escaping scheme either side adopts later.
func TestLinkUserinfoSurvivesAtSign(t *testing.T) {
	s := &SubService{address: "vpn.example.com", remarkModel: "-ieo"}

	const (
		email  = "alice@example.com"
		nasty  = "p@ss:w/rd?x#y"
		uuidV4 = "11111111-2222-3333-4444-555555555555"
	)

	cases := []struct {
		name     string
		inbound  *model.Inbound
		email    string
		wantUser string
		wantPass string
	}{
		{
			name: "naive: email username with an @",
			inbound: &model.Inbound{
				Id: 1, Port: 443, Protocol: model.NAIVE, Remark: "n",
				Settings:       `{"clients":[{"email":"alice@example.com","password":"p@ss:w/rd?x#y"}],"network":"tcp"}`,
				StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"n.example.com"}}`,
			},
			email: email, wantUser: email, wantPass: nasty,
		},
		{
			// The username is operator-typed, so it can carry an "@" without being an
			// address at all. It must escape exactly as the email fallback does, or the
			// field that was added to stop leaking the email becomes the new way to
			// hand out a link that dials somebody else's host.
			name: "naive: explicit username with an @",
			inbound: &model.Inbound{
				Id: 4, Port: 443, Protocol: model.NAIVE, Remark: "n",
				Settings:       `{"clients":[{"email":"alice","username":"alice@corp","password":"p@ss:w/rd?x#y"}],"network":"tcp"}`,
				StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"n.example.com"}}`,
			},
			email: "alice", wantUser: "alice@corp", wantPass: nasty,
		},
		{
			name: "tuic: password with an @",
			inbound: &model.Inbound{
				Id: 2, Port: 2053, Protocol: model.TUIC, Remark: "t",
				Settings:       `{"clients":[{"email":"bob","id":"11111111-2222-3333-4444-555555555555","password":"p@ss:w/rd?x#y"}]}`,
				StreamSettings: `{"network":"tuic","security":"tls","tlsSettings":{"serverName":"t.example.com"}}`,
			},
			email: "bob", wantUser: uuidV4, wantPass: nasty,
		},
		{
			name: "anytls: password with an @",
			inbound: &model.Inbound{
				Id: 3, Port: 8443, Protocol: model.ANYTLS, Remark: "a",
				Settings:       `{"clients":[{"email":"bob","password":"p@ss:w/rd?x#y"}]}`,
				StreamSettings: `{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}`,
			},
			email: "bob", wantUser: nasty, wantPass: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			link := s.getLink(c.inbound, c.email)
			if link == "" {
				t.Fatal("no link generated")
			}

			// The authority must hold exactly ONE "@", the userinfo separator. This is
			// the assertion that actually catches the bug: a link can round-trip through
			// Go's own parser and still be split differently by a client.
			authority := link[strings.Index(link, "://")+3:]
			if i := strings.IndexAny(authority, "/?#"); i >= 0 {
				authority = authority[:i]
			}
			if n := strings.Count(authority, "@"); n != 1 {
				t.Errorf("authority %q has %d '@', want exactly 1: %s", authority, n, link)
			}

			u, err := url.Parse(link)
			if err != nil {
				t.Fatalf("generated link does not parse: %v (%s)", err, link)
			}
			if got := u.Hostname(); got != "vpn.example.com" {
				t.Errorf("host = %q, want %q: the userinfo bled into the authority: %s", got, "vpn.example.com", link)
			}
			if got := u.User.Username(); got != c.wantUser {
				t.Errorf("username = %q, want %q", got, c.wantUser)
			}
			if pass, _ := u.User.Password(); pass != c.wantPass {
				t.Errorf("password = %q, want %q", pass, c.wantPass)
			}
		})
	}
}
