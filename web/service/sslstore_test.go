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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test certificate helpers.
//
// ECDSA P-256 throughout: these tests generate a lot of keys and RSA-2048 keygen
// would dominate the runtime for no added coverage. The one thing the production
// path does differently (--keylength 2048) is an acme.sh flag, covered by the
// argument tests, not by anything the store does.
// ---------------------------------------------------------------------------

type testCert struct {
	certPEM []byte
	keyPEM  []byte
	leaf    *x509.Certificate
	key     *ecdsa.PrivateKey
}

type testCertOpts struct {
	sans      []string
	notBefore time.Time
	notAfter  time.Time
	issuerCN  string // "" means self-signed
	// chain appends the signing certificate to the PEM bundle, i.e. a fullchain.
	chain bool
}

func makeTestCert(t *testing.T, opts testCertOpts) testCert {
	t.Helper()
	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, s := range opts.sans {
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		}
	}

	parent, parentKey := tmpl, leafKey
	var issuerDER []byte
	if opts.issuerCN != "" {
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ca key: %v", err)
		}
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
			Subject:               pkix.Name{CommonName: opts.issuerCN},
			NotBefore:             opts.notBefore.Add(-time.Hour),
			NotAfter:              opts.notAfter.Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		// The intermediate is itself signed by a root we never emit, so it is not
		// self-signed and therefore counts as an intermediate in describeChainPEM.
		rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate root key: %v", err)
		}
		rootTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano() + 2),
			Subject:               pkix.Name{CommonName: opts.issuerCN + " Root"},
			NotBefore:             opts.notBefore.Add(-2 * time.Hour),
			NotAfter:              opts.notAfter.Add(2 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
		if err != nil {
			t.Fatalf("create root: %v", err)
		}
		root, _ := x509.ParseCertificate(rootDER)
		issuerDER, err = x509.CreateCertificate(rand.Reader, caTmpl, root, &caKey.PublicKey, rootKey)
		if err != nil {
			t.Fatalf("create intermediate: %v", err)
		}
		parent, _ = x509.ParseCertificate(issuerDER)
		parentKey = caKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &leafKey.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if opts.chain && issuerDER != nil {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return testCert{
		certPEM: certPEM,
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		leaf:    leaf,
		key:     leafKey,
	}
}

// foreignKeyPEM is a well-formed key that belongs to no certificate here, for the
// mismatch cases.
func foreignKeyPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func newTestStore(t *testing.T) *SSLStore {
	t.Helper()
	s, err := OpenSSLStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenSSLStore: %v", err)
	}
	return s
}

// ---------------------------------------------------------------------------

func TestSSLStoreActivateValidPair(t *testing.T) {
	store := newTestStore(t)
	c := makeTestCert(t, testCertOpts{sans: []string{"example.com"}, issuerCN: "Test CA", chain: true})

	version, err := store.Stage("example.com", c.certPEM, c.keyPEM)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if store.HasActive() {
		t.Fatal("staging must not activate anything by itself")
	}
	if err := store.Activate(version); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// The active path has to be usable by exactly the code the listener uses.
	if err := ValidateCertPair(store.ActiveCertPath(), store.ActiveKeyPath()); err != nil {
		t.Fatalf("active pair does not load: %v", err)
	}

	// And it has to be a SYMLINK, because that is what makes the swap atomic and
	// what makes os.Stat in cert_reloader.go observe the change.
	fi, err := os.Lstat(filepath.Join(store.Root(), sslActiveLink))
	if err != nil {
		t.Fatalf("lstat active: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the active path must be a symlink")
	}

	info, err := store.ActiveInfo()
	if err != nil {
		t.Fatalf("ActiveInfo: %v", err)
	}
	if got := info.Identifiers; len(got) != 1 || got[0] != "example.com" {
		t.Errorf("Identifiers = %v, want [example.com]", got)
	}
	if !info.HasIntermediates {
		t.Error("a leaf plus intermediate must report HasIntermediates")
	}
	if info.KeyAlgorithm != "ECDSA" || info.KeyBits != 256 {
		t.Errorf("key = %s/%d, want ECDSA/256", info.KeyAlgorithm, info.KeyBits)
	}
	if !info.KeyMatchesLeaf {
		t.Error("KeyMatchesLeaf should be true for a matched pair")
	}
	if info.Issuer != "Test CA" {
		t.Errorf("Issuer = %q, want Test CA", info.Issuer)
	}
}

// The central invariant: a bad pair must never be able to displace a good one.
func TestSSLStoreRefusesMismatchedKeyAndKeepsActive(t *testing.T) {
	store := newTestStore(t)
	good := makeTestCert(t, testCertOpts{sans: []string{"good.example"}})
	version, err := store.Stage("good.example", good.certPEM, good.keyPEM)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := store.Activate(version); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	before := store.ActiveVersion()

	bad := makeTestCert(t, testCertOpts{sans: []string{"bad.example"}})
	if _, err := store.Stage("bad.example", bad.certPEM, foreignKeyPEM(t)); err == nil {
		t.Fatal("Stage accepted a key that does not match the certificate")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should name the mismatch, got %v", err)
	}

	if store.ActiveVersion() != before {
		t.Error("a refused stage moved the active link")
	}
	if err := ValidateCertPair(store.ActiveCertPath(), store.ActiveKeyPath()); err != nil {
		t.Fatalf("the previously active pair stopped working: %v", err)
	}
	info, err := store.ActiveInfo()
	if err != nil {
		t.Fatalf("ActiveInfo: %v", err)
	}
	if info.Identifiers[0] != "good.example" {
		t.Errorf("active is now %v, want the original good.example", info.Identifiers)
	}
}

func TestSSLStoreRefusesCorruptPEM(t *testing.T) {
	store := newTestStore(t)
	cases := []struct {
		name string
		cert []byte
		key  []byte
	}{
		{"garbage certificate", []byte("this is not a certificate"), foreignKeyPEM(t)},
		{"empty certificate", nil, foreignKeyPEM(t)},
		{"truncated PEM", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), foreignKeyPEM(t)},
		{"garbage key", makeTestCert(t, testCertOpts{sans: []string{"a.example"}}).certPEM, []byte("nope")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Stage("a.example", tc.cert, tc.key); err == nil {
				t.Fatal("Stage accepted an unusable pair")
			}
			if store.HasActive() {
				t.Fatal("a refused stage must never produce an active pair")
			}
		})
	}
}

// Activate re-validates, so a version corrupted on disk after staging (the
// rollback case) is still refused.
func TestSSLStoreActivateRevalidates(t *testing.T) {
	store := newTestStore(t)
	c := makeTestCert(t, testCertOpts{sans: []string{"example.com"}})
	version, err := store.Stage("example.com", c.certPEM, c.keyPEM)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := os.WriteFile(filepath.Join(version, sslKeyFileName), foreignKeyPEM(t), 0o600); err != nil {
		t.Fatalf("corrupt the version: %v", err)
	}
	if err := store.Activate(version); err == nil {
		t.Fatal("Activate accepted a version whose key no longer matches")
	}
	if store.HasActive() {
		t.Fatal("a refused activation must not leave an active link")
	}
}

// Staging certificates are refused with no bypass: their roots are in no trust
// store, so activating one takes the panel down for every browser while looking
// like a success.
func TestSSLStoreRefusesLetsEncryptStaging(t *testing.T) {
	store := newTestStore(t)
	c := makeTestCert(t, testCertOpts{sans: []string{"example.com"}, issuerCN: "(STAGING) Pretend Pear X1", chain: true})
	version, err := store.Stage("example.com", c.certPEM, c.keyPEM)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	err = store.Activate(version)
	if err == nil {
		t.Fatal("a staging certificate must not activate")
	}
	if !strings.Contains(err.Error(), "STAGING") {
		t.Errorf("the refusal should name staging, got %v", err)
	}
	info, err := InspectCertPair(filepath.Join(version, sslCertFileName), filepath.Join(version, sslKeyFileName))
	if err != nil {
		t.Fatalf("InspectCertPair: %v", err)
	}
	if !info.Staging {
		t.Error("the certificate should be flagged as staging")
	}
}

// The swap has to be observable through os.Stat, because that is the only thing
// cert_reloader.go looks at.
func TestSSLStoreSwapIsAtomicAndObservable(t *testing.T) {
	store := newTestStore(t)
	first := makeTestCert(t, testCertOpts{sans: []string{"first.example"}})
	second := makeTestCert(t, testCertOpts{sans: []string{"second.example"}})

	v1, err := store.Stage("first.example", first.certPEM, first.keyPEM)
	if err != nil {
		t.Fatalf("Stage first: %v", err)
	}
	if err := store.Activate(v1); err != nil {
		t.Fatalf("Activate first: %v", err)
	}
	before, err := os.Stat(store.ActiveCertPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	v2, err := store.Stage("second.example", second.certPEM, second.keyPEM)
	if err != nil {
		t.Fatalf("Stage second: %v", err)
	}
	if err := store.Activate(v2); err != nil {
		t.Fatalf("Activate second: %v", err)
	}

	after, err := os.Stat(store.ActiveCertPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// os.Stat follows the link, so size or mtime must differ or the reloader
	// would never notice the swap.
	if before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) {
		t.Error("the swap is invisible to a size+mtime check, so the running listener would not reload")
	}

	info, err := store.ActiveInfo()
	if err != nil {
		t.Fatalf("ActiveInfo: %v", err)
	}
	if info.Identifiers[0] != "second.example" {
		t.Errorf("active = %v, want second.example", info.Identifiers)
	}
	// Rollback: the old version is still there and still usable.
	if err := store.Activate(v1); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if info, _ := store.ActiveInfo(); info.Identifiers[0] != "first.example" {
		t.Errorf("after rollback active = %v, want first.example", info.Identifiers)
	}
}

func TestSSLStorePruneKeepsActive(t *testing.T) {
	store := newTestStore(t)
	var versions []string
	for i := 0; i < sslKeepVersions+3; i++ {
		c := makeTestCert(t, testCertOpts{sans: []string{"example.com"}})
		v, err := store.Stage("example.com", c.certPEM, c.keyPEM)
		if err != nil {
			t.Fatalf("Stage %d: %v", i, err)
		}
		versions = append(versions, v)
	}
	// Activate the OLDEST, then activate it again to trigger a prune while it is
	// the active one. It must survive even though it is well past the keep window.
	if err := store.Activate(versions[0]); err != nil {
		t.Fatalf("Activate oldest: %v", err)
	}
	if err := store.Activate(versions[0]); err != nil {
		t.Fatalf("re-Activate oldest: %v", err)
	}
	if err := ValidateCertPair(store.ActiveCertPath(), store.ActiveKeyPath()); err != nil {
		t.Fatalf("the active version was pruned out from under the link: %v", err)
	}
	if got := len(store.Versions("example.com")); got > sslKeepVersions+1 {
		t.Errorf("kept %d versions, want at most %d", got, sslKeepVersions+1)
	}
}

func TestSSLCertInfoLifetimeAndRenewal(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		notBefore  time.Time
		notAfter   time.Time
		wantDue    bool
		wantExpire bool
	}{
		{"fresh 90 day", now.Add(-24 * time.Hour), now.Add(89 * 24 * time.Hour), false, false},
		// A third of the lifetime before expiry is acme.sh's own 90/60 default.
		{"90 day at day 61", now.Add(-61 * 24 * time.Hour), now.Add(29 * 24 * time.Hour), true, false},
		{"fresh 160 hour", now.Add(-time.Hour), now.Add(159 * time.Hour), false, false},
		{"160 hour at 110h", now.Add(-110 * time.Hour), now.Add(50 * time.Hour), true, false},
		{"expired", now.Add(-100 * 24 * time.Hour), now.Add(-time.Hour), true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := makeTestCert(t, testCertOpts{sans: []string{"example.com"}, notBefore: tc.notBefore, notAfter: tc.notAfter})
			info, err := describeChainPEM(c.certPEM)
			if err != nil {
				t.Fatalf("describeChainPEM: %v", err)
			}
			if info.RenewalDue != tc.wantDue {
				t.Errorf("RenewalDue = %v, want %v (due at %s)", info.RenewalDue, tc.wantDue, info.RenewalDueAt)
			}
			if info.Expired != tc.wantExpire {
				t.Errorf("Expired = %v, want %v", info.Expired, tc.wantExpire)
			}
		})
	}
}

func TestSSLSetDirNameDistinguishesSets(t *testing.T) {
	// example.com and example.com+www are separate Let's Encrypt buckets, so they
	// must never share a directory even though they share a first identifier.
	a := sslSetDirName(SSLIdentifierSetKey([]string{"example.com"}))
	b := sslSetDirName(SSLIdentifierSetKey([]string{"example.com", "www.example.com"}))
	if a == b {
		t.Errorf("two different identifier sets share the directory name %q", a)
	}
	// A wildcard and an IPv6 literal both have to survive becoming a path.
	for _, key := range []string{"*.example.com", "2001:db8::1", "example.com,*.example.com"} {
		got := sslSetDirName(SSLIdentifierSetKey([]string{key}))
		if strings.ContainsAny(got, "*:/ ") {
			t.Errorf("sslSetDirName(%q) = %q, which is not a safe path element", key, got)
		}
	}
}

// A CA's intermediate carries the brand in the Organization and a bare code in
// the CommonName. Let's Encrypt's Generation Y intermediates are named YR1, YE1
// and so on, so preferring the CommonName reported a perfectly good certificate
// as issued by "YR1", which names nothing to the operator reading it.
func TestIssuerNameKeepsTheBrand(t *testing.T) {
	name := func(org, cn string) string {
		c := &x509.Certificate{}
		c.Issuer.CommonName = cn
		if org != "" {
			c.Issuer.Organization = []string{org}
		}
		return sslIssuerName(c)
	}
	cases := []struct{ org, cn, want string }{
		{"Let's Encrypt", "YR1", "Let's Encrypt (YR1)"},
		{"Let's Encrypt", "R11", "Let's Encrypt (R11)"},
		{"Google Trust Services", "WE1", "Google Trust Services (WE1)"},
		// Nothing to add in parentheses.
		{"Let's Encrypt", "", "Let's Encrypt"},
		{"", "YR1", "YR1"},
		// A self-signed certificate commonly repeats itself; saying it twice
		// would read as two different things.
		{"panel.example.com", "panel.example.com", "panel.example.com"},
	}
	for _, c := range cases {
		if got := name(c.org, c.cn); got != c.want {
			t.Errorf("sslIssuerName(O=%q, CN=%q) = %q, want %q", c.org, c.cn, got, c.want)
		}
	}
}
