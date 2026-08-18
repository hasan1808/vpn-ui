package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The slug becomes a directory holding a private key and it is derived from a name
// a CA gave us, so it has to come out inside the rules NormalizeSSLProfile enforces
// no matter what the certificate was called.
func TestSSLProfileNameForIsAlwaysAValidProfile(t *testing.T) {
	cases := []string{
		"panel.example.com",
		"*.example.com",
		"1.2.3.4",
		"2001:db8::1",
		"UPPER.Example.COM",
		strings.Repeat("very-long-name", 6) + ".example.com",
		"--weird--",
		"",
	}
	for _, in := range cases {
		got := SSLProfileNameFor([]string{in})
		norm, err := NormalizeSSLProfile(got)
		if err != nil {
			t.Errorf("SSLProfileNameFor(%q) = %q, which NormalizeSSLProfile refuses: %v", in, got, err)
			continue
		}
		if norm != got {
			t.Errorf("SSLProfileNameFor(%q) = %q but normalizes to %q; it should already be canonical", in, got, norm)
		}
	}
}

func TestSSLProfileNameForReadableSlugs(t *testing.T) {
	tests := map[string]string{
		"panel.example.com": "panel-example-com",
		"1.2.3.4":           "1-2-3-4",
		"SUB.Example.Com":   "sub-example-com",
	}
	for in, want := range tests {
		if got := SSLProfileNameFor([]string{in}); got != want {
			t.Errorf("SSLProfileNameFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// "default" is the reserved profile at the original store root. A certificate whose
// name happens to slug to it must not silently take that store over.
func TestSSLProfileNameForNeverStealsTheDefault(t *testing.T) {
	if got := SSLProfileNameFor([]string{"default"}); got == SSLDefaultProfile {
		t.Errorf("a certificate named %q produced the reserved profile name", "default")
	}
}

// Two long names sharing a head must not collapse onto one profile, or adopting the
// second would overwrite the first's store.
func TestSSLProfileNameForLongNamesStayDistinct(t *testing.T) {
	a := SSLProfileNameFor([]string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.one.example.com"})
	b := SSLProfileNameFor([]string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.two.example.com"})
	if a == b {
		t.Errorf("two different long names both slugged to %q", a)
	}
	for _, s := range []string{a, b} {
		if len(s) > 32 {
			t.Errorf("slug %q is %d chars, over the 32 the profile rules allow", s, len(s))
		}
	}
}

// A path inside a managed store is never adoptable: adopting it would copy the
// store's own active certificate back into the store as a new version.
func TestSSLInsideManagedStore(t *testing.T) {
	root := DefaultSSLStoreRoot()
	in := filepath.Join(root, "active", "fullchain.pem")
	if !sslInsideManagedStore(in) {
		t.Errorf("%q is inside the store %q but was not recognised", in, root)
	}
	out := filepath.Join(filepath.Dir(root), "fullchain.pem")
	if sslInsideManagedStore(out) {
		t.Errorf("%q sits beside the store, not in it, yet was treated as managed", out)
	}
	// The classic traversal shape must not read as "inside" just because the prefix
	// matches as a string.
	sneaky := filepath.Join(root, "..", "..", "etc", "fullchain.pem")
	if sslInsideManagedStore(sneaky) {
		t.Errorf("%q escapes the store but was treated as inside it", sneaky)
	}
}

// Identity is issuer+serial, so a RENEWAL for the same names is a different
// certificate (and stays offerable) while one certificate reachable by two paths is
// one thing (and is offered once).
func TestSSLCertIdentityDistinguishesRenewals(t *testing.T) {
	a := &SSLCertInfo{Issuer: "CN=Test CA", Serial: "01", Identifiers: []string{"a.example"}}
	sameCert := &SSLCertInfo{Issuer: "CN=Test CA", Serial: "01", Identifiers: []string{"a.example"}}
	renewed := &SSLCertInfo{Issuer: "CN=Test CA", Serial: "02", Identifiers: []string{"a.example"}}
	otherCA := &SSLCertInfo{Issuer: "CN=Other CA", Serial: "01", Identifiers: []string{"a.example"}}

	if sslCertIdentity(a) != sslCertIdentity(sameCert) {
		t.Error("the same certificate compared as two different ones")
	}
	if sslCertIdentity(a) == sslCertIdentity(renewed) {
		t.Error("a renewal compared equal to the certificate it replaces, so it could never be adopted")
	}
	if sslCertIdentity(a) == sslCertIdentity(otherCA) {
		t.Error("serials are only unique per issuer, so two issuers' serial 01 must not collide")
	}
	if sslCertIdentity(nil) != "" {
		t.Error("a nil info must not produce an identity that could match a real one")
	}
}

func TestAdoptRefusesAPairThatIsNotOne(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "fullchain.pem")
	key := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(cert, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &SSLService{}
	if _, err := s.AdoptCertificate("junk", cert, key); err == nil {
		t.Error("adopting unparseable files succeeded; it must refuse before anything is staged")
	}
}

func TestAdoptRefusesEmptyPaths(t *testing.T) {
	s := &SSLService{}
	if _, err := s.AdoptCertificate("x", "", ""); err == nil {
		t.Error("adopting with no paths succeeded")
	}
}

// Adopting the store's own active path would copy a managed certificate back into
// the store it already lives in.
func TestAdoptRefusesAPathInsideTheStore(t *testing.T) {
	s := &SSLService{}
	inside := filepath.Join(DefaultSSLStoreRoot(), "active", "fullchain.pem")
	_, err := s.AdoptCertificate("x", inside, filepath.Join(DefaultSSLStoreRoot(), "active", "privkey.pem"))
	if err == nil || !strings.Contains(err.Error(), "already inside") {
		t.Errorf("adopting a path inside the store returned %v, want a refusal naming the store", err)
	}
}

// A wildcard and its bare domain are DIFFERENT certificates covering different
// names, so they must not share a store. They used to both slug to "example-com",
// which meant issuing for one took over the other's store and re-pointed whatever
// listener was serving it.
func TestSSLProfileNameForSeparatesWildcardFromBareDomain(t *testing.T) {
	bare := SSLProfileNameFor([]string{"example.com"})
	wild := SSLProfileNameFor([]string{"*.example.com"})
	if bare == wild {
		t.Fatalf("example.com and *.example.com both produced %q, so one would overwrite the other", bare)
	}
	if norm, err := NormalizeSSLProfile(wild); err != nil || norm != wild {
		t.Errorf("wildcard slug %q is not a name the store accepts: %v", wild, err)
	}
	if !strings.Contains(wild, "wildcard") {
		t.Errorf("wildcard slug %q does not say it is a wildcard, so the row is unreadable", wild)
	}
	// Different wildcards still have to be distinct from each other.
	if SSLProfileNameFor([]string{"*.a.example.com"}) == SSLProfileNameFor([]string{"*.b.example.com"}) {
		t.Error("two different wildcards collapsed onto one profile")
	}
}
