package sub

import (
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// These lock genMtprotoLink to MtprotoUser.links() in web/assets/js/model/inbound.js
// byte for byte. The raw subscription link is generated in both Go and JS and the two
// must match exactly, so any drift here is a real bug (see the xhttp parity work).

func mtprotoInbound(port int, clientJSON string) *model.Inbound {
	return &model.Inbound{
		Protocol: model.MTPROTO,
		Port:     port,
		Settings: `{"clients":[` + clientJSON + `]}`,
	}
}

func TestGenMtprotoLinkParity(t *testing.T) {
	s := &SubService{address: "1.2.3.4"}
	const secret = "0123456789abcdef0123456789abcdef"
	inbound := mtprotoInbound(443,
		`{"email":"u","secret":"`+secret+`","modeClassic":true,"modeSecure":true,"modeTls":true,"tlsDomain":"www.google.com"}`)

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
	inbound := mtprotoInbound(9, `{"email":"u","secret":"`+secret+`","modeSecure":true}`)
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
	inbound := mtprotoInbound(1, `{"email":"u","secret":"`+secret+`","modeTls":true,"tlsDomain":"   "}`)
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
		`{"email":"u","secret":"`+secret+`","modeClassic":true,"modeSecure":true,`+
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
