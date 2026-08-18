package sub

import (
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// These lock genMtprotoLink to MtprotoUser.links() in web/assets/js/model/inbound.js
// byte for byte. The raw subscription link is generated in both Go and JS and the two
// must match exactly, so any drift here is a real bug (see the xhttp parity work).
//
// The modes and the FakeTLS domain are read off the INBOUND, not the subscriber's
// client entry: the proxy applies both process-wide, so a link built from per-client
// keys would offer transports it refuses.

func mtprotoInbound(port int, proxyJSON, clientJSON string) *model.Inbound {
	return &model.Inbound{
		Protocol: model.MTPROTO,
		Port:     port,
		Settings: `{` + proxyJSON + `"clients":[` + clientJSON + `]}`,
	}
}

func TestGenMtprotoLinkParity(t *testing.T) {
	s := &SubService{address: "1.2.3.4"}
	const secret = "0123456789abcdef0123456789abcdef"
	inbound := mtprotoInbound(443,
		`"modeClassic":true,"modeSecure":true,"modeTls":true,"tlsDomain":"www.google.com",`,
		`{"email":"u","secret":"`+secret+`"}`)

	got := s.genMtprotoLink(inbound, "u")
	// classic, secure ("dd"), tls ("ee"+secret+hex("www.google.com")), in that order.
	want := "tg://proxy?server=1.2.3.4&port=443&secret=" + secret + "\n" +
		"tg://proxy?server=1.2.3.4&port=443&secret=dd" + secret + "\n" +
		"tg://proxy?server=1.2.3.4&port=443&secret=ee" + secret + "7777772e676f6f676c652e636f6d"
	if got != want {
		t.Fatalf("mtproto links mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestGenMtprotoLinkSecureOnly(t *testing.T) {
	s := &SubService{address: "h"}
	const secret = "abcabcabcabcabcabcabcabcabcabc12"
	inbound := mtprotoInbound(9, `"modeSecure":true,`, `{"email":"u","secret":"`+secret+`"}`)
	if got, want := s.genMtprotoLink(inbound, "u"), "tg://proxy?server=h&port=9&secret=dd"+secret; got != want {
		t.Fatalf("secure-only mismatch:\n got=%q\nwant=%q", got, want)
	}
}

// JS applies the www.google.com default BEFORE the trim, so a whitespace-only domain
// trims to "" and contributes an empty hex suffix. Lock that quirk so a "cleanup" that
// trims first (turning "   " back into the default) does not silently diverge.
func TestGenMtprotoLinkWhitespaceTlsDomainEmptyHex(t *testing.T) {
	s := &SubService{address: "h"}
	const secret = "1111111111111111111111111111111f"
	inbound := mtprotoInbound(1, `"modeTls":true,"tlsDomain":"   ",`, `{"email":"u","secret":"`+secret+`"}`)
	if got, want := s.genMtprotoLink(inbound, "u"), "tg://proxy?server=h&port=1&secret=ee"+secret; got != want {
		t.Fatalf("whitespace-domain mismatch:\n got=%q\nwant=%q", got, want)
	}
}

// Every external-proxy endpoint is emitted (no empty-dest filter, no port fallback),
// endpoint-outer / mode-inner, and the server value is encodeURIComponent'd.
func TestGenMtprotoLinkExternalProxyEscapesServerAndFansOut(t *testing.T) {
	s := &SubService{address: "ignored"}
	const secret = "2222222222222222222222222222222e"
	inbound := mtprotoInbound(443,
		`"modeClassic":true,"modeSecure":true,`,
		`{"email":"u","secret":"`+secret+`",`+
			`"externalProxy":[{"dest":"a b.com","port":8443},{"dest":"c.com","port":9443}]}`)
	got := s.genMtprotoLink(inbound, "u")
	want := "tg://proxy?server=a%20b.com&port=8443&secret=" + secret + "\n" +
		"tg://proxy?server=a%20b.com&port=8443&secret=dd" + secret + "\n" +
		"tg://proxy?server=c.com&port=9443&secret=" + secret + "\n" +
		"tg://proxy?server=c.com&port=9443&secret=dd" + secret
	if got != want {
		t.Fatalf("external-proxy fanout mismatch:\n got=%q\nwant=%q", got, want)
	}
}

// An inbound still in the pre-move shape (its modes and FakeTLS domain on its CLIENTS)
// must hand the subscriber the same links as the equivalent already-migrated one.
//
// Subscriptions are served from the moment the panel is up and by the sub listener,
// neither of which waits for the startup lift, and a restored backup or an API write can
// put an inbound back into that shape at any time. Resolving to the fresh-inbound
// defaults instead would offer transports the proxy refuses.
func TestGenMtprotoLinkResolvesTheLegacyShape(t *testing.T) {
	s := &SubService{address: "1.2.3.4"}
	const secret = "0123456789abcdef0123456789abcdef"

	// alice holds only "secure", bob holds FakeTLS with a domain, so the inbound's
	// resolved set is secure+tls and the domain is bob's.
	legacy := mtprotoInbound(443, ``,
		`{"email":"alice","secret":"`+secret+`","modeSecure":true},`+
			`{"email":"bob","secret":"ffeeddccbbaa99887766554433221100","modeTls":true,"tlsDomain":"www.cloudflare.com"}`)
	migrated := mtprotoInbound(443,
		`"modeClassic":false,"modeSecure":true,"modeTls":true,"tlsDomain":"www.cloudflare.com",`,
		`{"email":"alice","secret":"`+secret+`"},`+
			`{"email":"bob","secret":"ffeeddccbbaa99887766554433221100"}`)

	got, want := s.genMtprotoLink(legacy, "alice"), s.genMtprotoLink(migrated, "alice")
	if want == "" {
		t.Fatal("the migrated inbound produced no links, so this test is not comparing anything")
	}
	if got != want {
		t.Fatalf("legacy-shape links differ from the migrated ones:\n got=%q\nwant=%q", got, want)
	}
	// Spelled out, so a change of resolution rule is visible here and not only as a
	// mismatch: secure ("dd") and FakeTLS ("ee" + hex of the INBOUND's domain), no
	// classic, because no account asked for it.
	const clouflareHex = "7777772e636c6f7564666c6172652e636f6d"
	if want != "tg://proxy?server=1.2.3.4&port=443&secret=dd"+secret+"\n"+
		"tg://proxy?server=1.2.3.4&port=443&secret=ee"+secret+clouflareHex {
		t.Fatalf("unexpected link set: %q", want)
	}
}

// The characters where url.QueryEscape diverges from JS encodeURIComponent, which is
// exactly why genMtprotoLink must not use it.
func TestEncodeURIComponentGoMatchesJS(t *testing.T) {
	cases := map[string]string{
		"a b":     "a%20b", // space -> %20, not '+'
		"a!b":     "a!b",   // ! kept
		"a(b)":    "a(b)",  // ( ) kept
		"a*b":     "a*b",   // * kept
		"a'b":     "a'b",   // ' kept
		"a/b?c=d": "a%2Fb%3Fc%3Dd",
		"é":  "%C3%A9", // each UTF-8 byte percent-encoded
	}
	for in, want := range cases {
		if got := encodeURIComponentGo(in); got != want {
			t.Errorf("encodeURIComponentGo(%q)=%q want %q", in, got, want)
		}
	}
}

// The inbound-level External Proxy is the default for accounts that name none of
// their own, so an account with an empty list gets the inbound's endpoints rather
// than the panel host.
func TestGenMtprotoLinkFallsBackToTheInboundExternalProxy(t *testing.T) {
	s := &SubService{address: "panel.host"}
	const secret = "3333333333333333333333333333333a"
	inbound := mtprotoInbound(443,
		`"modeClassic":true,"externalProxy":[{"dest":"relay.example","port":8443}],`,
		`{"email":"u","secret":"`+secret+`"}`)
	got := s.genMtprotoLink(inbound, "u")
	want := "tg://proxy?server=relay.example&port=8443&secret=" + secret
	if got != want {
		t.Fatalf("the inbound's endpoint was not used for an account with none:\n got=%q\nwant=%q", got, want)
	}
}

// And the account's own list REPLACES the inbound's rather than adding to it: both
// answer "where do this account's links point", so a merge would keep handing out the
// endpoint the operator overrode.
func TestGenMtprotoLinkClientExternalProxyOverridesTheInbound(t *testing.T) {
	s := &SubService{address: "panel.host"}
	const secret = "444444444444444444444444444444ab"
	inbound := mtprotoInbound(443,
		`"modeClassic":true,"externalProxy":[{"dest":"shared.example","port":8443}],`,
		`{"email":"u","secret":"`+secret+`","externalProxy":[{"dest":"mine.example","port":9443}]}`)
	got := s.genMtprotoLink(inbound, "u")
	want := "tg://proxy?server=mine.example&port=9443&secret=" + secret
	if got != want {
		t.Fatalf("the account's own endpoint did not win:\n got=%q\nwant=%q", got, want)
	}
}

// With neither list set nothing changes: the panel's own address stands.
func TestGenMtprotoLinkNoExternalProxyUsesPanelHost(t *testing.T) {
	s := &SubService{address: "panel.host"}
	const secret = "55555555555555555555555555555abc"
	inbound := mtprotoInbound(443, `"modeClassic":true,`, `{"email":"u","secret":"`+secret+`"}`)
	got := s.genMtprotoLink(inbound, "u")
	want := "tg://proxy?server=panel.host&port=443&secret=" + secret
	if got != want {
		t.Fatalf("panel-host fallback mismatch:\n got=%q\nwant=%q", got, want)
	}
}
