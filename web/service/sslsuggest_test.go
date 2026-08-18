package service

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// suggestDeps is a host where every probe answers however the test says.
func suggestDeps(port80Err error) sslPreflightDeps {
	return sslPreflightDeps{
		portFree: func(int) error { return port80Err },
		localIPs: func() ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil },
		publicIP: func() string { return "203.0.113.10" },
		lookupIP: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil },
	}
}

func TestSuggestNameWithFreePort80UsesHTTP(t *testing.T) {
	got := sslSuggest([]string{"panel.example.com"}, suggestDeps(nil))
	if got.Blocked {
		t.Fatalf("blocked with a free port 80: %s", got.Reason)
	}
	if got.Challenge != SSLChallengeStandaloneDomain {
		t.Errorf("challenge = %q, want %q", got.Challenge, SSLChallengeStandaloneDomain)
	}
	if got.NeedsToken {
		t.Error("asked for a Cloudflare token on the port 80 path")
	}
	if got.Reason == "" {
		t.Error("no reason given; the reason is the whole justification the operator sees")
	}
}

// A busy port 80 is normal and permanent on a host running its own webserver.
// The suggestion has to fall through to the method that needs nothing stopped.
func TestSuggestNameWithBusyPort80FallsToDNS(t *testing.T) {
	got := sslSuggest([]string{"panel.example.com"}, suggestDeps(errors.New("address already in use")))
	if got.Blocked {
		t.Fatalf("blocked, but DNS-01 needs no port: %s", got.Reason)
	}
	if got.Challenge != SSLChallengeCloudflareDNS {
		t.Errorf("challenge = %q, want %q", got.Challenge, SSLChallengeCloudflareDNS)
	}
	if !got.NeedsToken {
		t.Error("DNS-01 through Cloudflare cannot run without a token, but none was asked for")
	}
	if !strings.Contains(got.Reason, "80") {
		t.Errorf("reason %q does not name port 80, so the operator cannot tell why the method changed", got.Reason)
	}
}

// An IP has nothing to put a TXT record on, so a busy port 80 is fatal rather
// than a reason to pick another method.
func TestSuggestIPWithBusyPort80IsBlocked(t *testing.T) {
	got := sslSuggest([]string{"203.0.113.10"}, suggestDeps(errors.New("address already in use")))
	if !got.Blocked {
		t.Fatalf("an IP with no free port 80 has no method at all, got challenge %q", got.Challenge)
	}
	if got.Challenge != "" {
		t.Errorf("a blocked suggestion still named challenge %q, which a client could send", got.Challenge)
	}
}

func TestSuggestIPWithFreePort80UsesIPChallenge(t *testing.T) {
	got := sslSuggest([]string{"203.0.113.10"}, suggestDeps(nil))
	if got.Blocked {
		t.Fatalf("blocked: %s", got.Reason)
	}
	if got.Challenge != SSLChallengeStandaloneIP {
		t.Errorf("challenge = %q, want %q", got.Challenge, SSLChallengeStandaloneIP)
	}
	// The six-day lifetime is the single most surprising thing about an IP
	// certificate, so it has to be in the sentence shown before the request.
	if !strings.Contains(got.Reason, "six days") {
		t.Errorf("reason %q does not warn that an IP certificate is short-lived", got.Reason)
	}
}

// A wildcard is DNS-01 only, whatever port 80 is doing.
func TestSuggestWildcardAlwaysUsesDNS(t *testing.T) {
	for _, port80 := range []error{nil, errors.New("busy")} {
		got := sslSuggest([]string{"*.example.com"}, suggestDeps(port80))
		if got.Challenge != SSLChallengeCloudflareDNS {
			t.Errorf("port80=%v: challenge = %q, want %q", port80, got.Challenge, SSLChallengeCloudflareDNS)
		}
		if !got.NeedsToken {
			t.Errorf("port80=%v: a wildcard needs a Cloudflare token", port80)
		}
	}
}

// Mixing a name with an IP cannot be fixed by choosing a different method, so it
// blocks rather than suggesting one that will fail.
func TestSuggestMixedNameAndIPIsBlocked(t *testing.T) {
	got := sslSuggest([]string{"panel.example.com", "203.0.113.10"}, suggestDeps(nil))
	if !got.Blocked {
		t.Fatalf("a mixed set was allowed with challenge %q", got.Challenge)
	}
	if !strings.Contains(got.Reason, "two") {
		t.Errorf("reason %q does not tell the operator what to do instead", got.Reason)
	}
}

func TestSuggestEmptyIsBlockedNotCrashed(t *testing.T) {
	for _, in := range [][]string{nil, {}, {"", "   "}} {
		got := sslSuggest(in, suggestDeps(nil))
		if !got.Blocked {
			t.Errorf("%q produced challenge %q instead of asking for an address", in, got.Challenge)
		}
	}
}

// The order the operator typed has to survive: the first identifier becomes the
// certificate's filename in the acme.sh state directory and the name every later
// renewal is addressed by. NormalizeSSLIdentifiers sorts, so it must not be what
// this uses.
func TestSuggestKeepsIdentifierOrder(t *testing.T) {
	got := sslSuggest([]string{"zeta.example.com", "alpha.example.com"}, suggestDeps(nil))
	if len(got.Identifiers) != 2 || got.Identifiers[0] != "zeta.example.com" {
		t.Errorf("identifiers = %v, want zeta first as typed", got.Identifiers)
	}
}

func TestSuggestCleansIdentifiers(t *testing.T) {
	got := sslSuggest([]string{" PANEL.Example.COM. ", "panel.example.com", ""}, suggestDeps(nil))
	if len(got.Identifiers) != 1 || got.Identifiers[0] != "panel.example.com" {
		t.Errorf("identifiers = %v, want one cleaned name", got.Identifiers)
	}
}

// The profile is where the certificate lands on disk, so a suggestion that did
// not name one would leave the client deriving a store path in JavaScript.
func TestSuggestNamesAProfile(t *testing.T) {
	got := sslSuggest([]string{"panel.example.com"}, suggestDeps(nil))
	if got.Profile == "" {
		t.Fatal("no profile named")
	}
	if norm, err := NormalizeSSLProfile(got.Profile); err != nil || norm != got.Profile {
		t.Errorf("profile %q is not one the store would accept: %v", got.Profile, err)
	}
}

// A name pointing somewhere else is the likeliest reason an HTTP-01 attempt
// fails, and a failure costs a rate-limit slot. It must reach the operator before
// the request, as a warning rather than a refusal.
func TestSuggestWarnsWhenTheNamePointsElsewhere(t *testing.T) {
	deps := suggestDeps(nil)
	deps.lookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.7")}, nil }
	got := sslSuggest([]string{"panel.example.com"}, deps)
	if got.Blocked {
		t.Fatal("a name pointing elsewhere blocked the suggestion; the preflight in the run is the gate, not this")
	}
	if len(got.Warnings) == 0 {
		t.Error("no warning that the name does not resolve to this server")
	}
}
