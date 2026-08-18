package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/web/service"
)

// updateCert stores certificate paths straight from the CLI, bypassing the
// settings form's AllSetting.CheckValid (web/entity/entity.go:140-152). That
// asymmetry is the bug these tests pin down: a pair stored here that does not load
// takes the panel down to plain HTTP at the NEXT restart, with one log line
// (web/web.go:541-556), which is a failure nobody connects back to the command
// that caused it.
//
// The refusal path returns before database.InitDB, so these need no database at
// all. That ordering is deliberate: a refused command should leave nothing behind.

// writeCertPair emits a self-signed pair and returns both paths. When mismatch is
// true the key belongs to a DIFFERENT certificate, which is the case
// tls.LoadX509KeyPair catches and the case an operator actually hits (copying the
// wrong privkey.pem out of an acme.sh directory).
func writeCertPair(t *testing.T, dir, name string, mismatch bool) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	emit := key
	if mismatch {
		if emit, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	keyDER, err := x509.MarshalECPrivateKey(emit)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// captureStdout runs fn with stdout redirected and returns what it printed.
// updateCert reports through fmt.Print rather than returning an error, so this is
// the only way to assert on its behaviour.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

func TestUpdateCertRefusesUnusablePairs(t *testing.T) {
	dir := t.TempDir()
	goodCert, goodKey := writeCertPair(t, dir, "good", false)
	_, foreignKey := writeCertPair(t, dir, "foreign", true)

	garbage := filepath.Join(dir, "garbage.crt")
	if err := os.WriteFile(garbage, []byte("this is not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		cert string
		key  string
	}{
		// The realistic one: the wrong privkey.pem copied out of an acme.sh dir.
		{"key does not match the certificate", goodCert, foreignKey},
		{"certificate is not PEM", garbage, goodKey},
		{"certificate file is missing", filepath.Join(dir, "absent.crt"), goodKey},
		{"key file is missing", goodCert, filepath.Join(dir, "absent.key")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A DB folder that must stay untouched: reaching InitDB would create
			// vpn-ui.db here, so an empty directory afterwards proves the refusal
			// happened before anything was opened or written.
			dbDir := t.TempDir()
			t.Setenv("VPNUI_DB_FOLDER", dbDir)

			out := captureStdout(t, func() { updateCert(tc.cert, tc.key) })

			if !strings.Contains(out, "refusing to store this certificate") {
				t.Fatalf("the pair was not refused; output was:\n%s", out)
			}
			if !strings.Contains(out, "Nothing was changed") {
				t.Errorf("the refusal should say nothing was changed, got:\n%s", out)
			}
			// The message has to name the offending paths, since the operator
			// typed them and one of the two is wrong.
			if !strings.Contains(out, tc.cert) || !strings.Contains(out, tc.key) {
				t.Errorf("the refusal should name both paths, got:\n%s", out)
			}
			if strings.Contains(out, "success") {
				t.Errorf("a refused pair must not report any setting as stored, got:\n%s", out)
			}

			entries, err := os.ReadDir(dbDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("a refused command must not touch the database, found %v", entries)
			}
		})
	}
}

// One bad invocation would otherwise degrade BOTH listeners, since updateCert
// points webCertFile, webKeyFile, subCertFile and subKeyFile at the same pair.
func TestUpdateCertRefusalCoversSubscriptionListenerToo(t *testing.T) {
	dir := t.TempDir()
	goodCert, _ := writeCertPair(t, dir, "good", false)
	_, foreignKey := writeCertPair(t, dir, "foreign", true)
	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())

	out := captureStdout(t, func() { updateCert(goodCert, foreignKey) })
	for _, phrase := range []string{
		"set certificate public key success",
		"set certificate for subscription public key success",
	} {
		if strings.Contains(out, phrase) {
			t.Errorf("a refused pair reached the settings writes (%q):\n%s", phrase, out)
		}
	}
}

// Clearing is a legitimate request to stop serving TLS, so it must not be caught
// by a check whose whole subject is a pair that does not exist.
func TestUpdateCertStillAcceptsClearing(t *testing.T) {
	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())
	out := captureStdout(t, func() { updateCert("", "") })
	if strings.Contains(out, "refusing to store this certificate") {
		t.Errorf("clearing the certificate must not be refused, got:\n%s", out)
	}
}

// And the guard must not have turned a valid pair into a rejection.
func TestUpdateCertAcceptsAValidPair(t *testing.T) {
	dir := t.TempDir()
	goodCert, goodKey := writeCertPair(t, dir, "good", false)
	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())

	out := captureStdout(t, func() { updateCert(goodCert, goodKey) })
	if strings.Contains(out, "refusing to store this certificate") {
		t.Fatalf("a valid pair was refused:\n%s", out)
	}
	for _, phrase := range []string{
		"set certificate public key success",
		"set certificate private key success",
	} {
		if !strings.Contains(out, phrase) {
			t.Errorf("expected %q in the output, got:\n%s", phrase, out)
		}
	}
}

// Half a pair is not something any listener can serve, and both entry points have
// to say so rather than storing it.
func TestCertCommandsRefuseHalfAPair(t *testing.T) {
	dir := t.TempDir()
	goodCert, goodKey := writeCertPair(t, dir, "good", false)
	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())

	for name, fn := range map[string]func(string, string){
		"panel":        updateCert,
		"subscription": updateSubCert,
	} {
		for _, tc := range []struct{ cert, key string }{{goodCert, ""}, {"", goodKey}} {
			out := captureStdout(t, func() { fn(tc.cert, tc.key) })
			if !strings.Contains(out, "both public and private key should be entered") {
				t.Errorf("%s listener, cert=%q key=%q: expected the both-or-neither refusal, got:\n%s", name, tc.cert, tc.key, out)
			}
			if strings.Contains(out, "success") {
				t.Errorf("%s listener, cert=%q key=%q: half a pair reached the settings writes:\n%s", name, tc.cert, tc.key, out)
			}
		}
	}
}

// THE BUG: a flag named -webCert moved the SUBSCRIPTION server too.
//
// subCertFile is "" on a fresh install, and an empty subCertFile used to count as
// "the subscription server follows the panel". Both installers run this command as
// part of one (vpn-ui.sh with -webCert after acme.sh, deploy.sh with -selfsign), so
// every install put the panel's certificate on a subscription listener nobody had
// asked to serve TLS. Empty means never configured, and this command has to leave it
// that way.
func TestUpdateCertLeavesAnUnconfiguredSubscriptionListenerAlone(t *testing.T) {
	dir := t.TempDir()
	goodCert, goodKey := writeCertPair(t, dir, "good", false)
	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())

	out := captureStdout(t, func() { updateCert(goodCert, goodKey) })
	for _, phrase := range []string{
		"set certificate for subscription public key success",
		"set certificate for subscription private key success",
	} {
		if strings.Contains(out, phrase) {
			t.Errorf("-webCert wrote the subscription listener's setting (%q):\n%s", phrase, out)
		}
	}
	// It has to SAY what it did not touch, since the operator asked for one
	// listener and this is the sentence that tells them the other one is elsewhere.
	if !strings.Contains(out, "subscription server: NOT changed") {
		t.Errorf("the output should name the listener it left alone, got:\n%s", out)
	}

	// The setting itself is the thing sub/sub.go reads, so assert on it and not
	// only on what was printed.
	var ss service.SettingService
	got, err := ss.GetSubCertFile()
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("subCertFile should still be empty, got %q", got)
	}
}

// The other half of the same rule: when the two settings genuinely named ONE file,
// leaving the subscription server behind would be the surprise, because its setting
// would go on naming a file this command has just replaced.
func TestUpdateCertMovesASubscriptionListenerThatFollowedThePanel(t *testing.T) {
	dir := t.TempDir()
	certA, keyA := writeCertPair(t, dir, "a", false)
	certB, keyB := writeCertPair(t, dir, "b", false)
	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())

	// The state an operator reaches by switching both listeners on in the SSL
	// manager. updateCert runs first only because it is what opens the database.
	captureStdout(t, func() { updateCert(certA, keyA) })
	var ss service.SettingService
	if err := ss.SetSubCertFile(certA); err != nil {
		t.Fatal(err)
	}
	if err := ss.SetSubKeyFile(keyA); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { updateCert(certB, keyB) })
	if !strings.Contains(out, "set certificate for subscription public key success") {
		t.Errorf("a subscription listener on the panel's own file should follow it, got:\n%s", out)
	}
	if got, err := ss.GetSubCertFile(); err != nil || got != certB {
		t.Errorf("subCertFile: got %q (err %v), want %q", got, err, certB)
	}
}

// And a deliberate split survives, which it already did.
func TestUpdateCertLeavesASplitSubscriptionListenerAlone(t *testing.T) {
	dir := t.TempDir()
	certA, keyA := writeCertPair(t, dir, "a", false)
	certB, keyB := writeCertPair(t, dir, "b", false)
	certC, keyC := writeCertPair(t, dir, "c", false)
	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())

	captureStdout(t, func() { updateCert(certA, keyA) })
	var ss service.SettingService
	if err := ss.SetSubCertFile(certB); err != nil {
		t.Fatal(err)
	}
	if err := ss.SetSubKeyFile(keyB); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { updateCert(certC, keyC) })
	if !strings.Contains(out, certB) {
		t.Errorf("the output should name the certificate the subscription server keeps, got:\n%s", out)
	}
	if got, err := ss.GetSubCertFile(); err != nil || got != certB {
		t.Errorf("subCertFile: got %q (err %v), want %q", got, err, certB)
	}
}

// -subCert is the flag that says "put the subscription server on this", and it is
// the only one that may move it. It must not touch the panel on the way past.
func TestUpdateSubCertMovesOnlyTheSubscriptionListener(t *testing.T) {
	dir := t.TempDir()
	panelCert, panelKey := writeCertPair(t, dir, "panel", false)
	subCert, subKey := writeCertPair(t, dir, "sub", false)
	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())

	captureStdout(t, func() { updateCert(panelCert, panelKey) })
	out := captureStdout(t, func() { updateSubCert(subCert, subKey) })

	for _, phrase := range []string{
		"set certificate for subscription public key success",
		"set certificate for subscription private key success",
		"panel: NOT changed",
	} {
		if !strings.Contains(out, phrase) {
			t.Errorf("expected %q in the output, got:\n%s", phrase, out)
		}
	}

	var ss service.SettingService
	if got, err := ss.GetCertFile(); err != nil || got != panelCert {
		t.Errorf("webCertFile: got %q (err %v), want %q", got, err, panelCert)
	}
	if got, err := ss.GetSubCertFile(); err != nil || got != subCert {
		t.Errorf("subCertFile: got %q (err %v), want %q", got, err, subCert)
	}
}

// The subscription listener degrades to plain HTTP on a bad pair exactly the way
// the panel does, and it degrades where fewer people are looking, so the same
// refusal guards it and it lands before the database is opened.
func TestUpdateSubCertRefusesAnUnusablePair(t *testing.T) {
	dir := t.TempDir()
	goodCert, _ := writeCertPair(t, dir, "good", false)
	_, foreignKey := writeCertPair(t, dir, "foreign", true)
	dbDir := t.TempDir()
	t.Setenv("VPNUI_DB_FOLDER", dbDir)

	out := captureStdout(t, func() { updateSubCert(goodCert, foreignKey) })
	if !strings.Contains(out, "refusing to store this certificate") {
		t.Fatalf("the pair was not refused; output was:\n%s", out)
	}
	if strings.Contains(out, "success") {
		t.Errorf("a refused pair must not report any setting as stored, got:\n%s", out)
	}
	entries, err := os.ReadDir(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("a refused command must not touch the database, found %v", entries)
	}
}

// Which listeners an invocation moves, decided from the flags that were TYPED.
// The case that matters is the last one: without it, setting the subscription
// server's certificate would clear the panel's, since an absent -webCert is an
// empty pair and an empty pair means "stop serving TLS".
func TestCertCommandTargets(t *testing.T) {
	cases := []struct {
		name  string
		typed []string
		panel bool
		sub   bool
	}{
		{"a bare `vpn-ui cert` still clears the panel", nil, true, false},
		{"-webCert moves the panel only", []string{"webCert", "webCertKey"}, true, false},
		{"-subCert moves the subscription server only", []string{"subCert", "subCertKey"}, false, true},
		{"both pairs move both listeners", []string{"webCert", "webCertKey", "subCert", "subCertKey"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			typed := map[string]bool{}
			for _, f := range tc.typed {
				typed[f] = true
			}
			panel, sub := certCommandTargets(typed)
			if panel != tc.panel || sub != tc.sub {
				t.Errorf("got panel=%v sub=%v, want panel=%v sub=%v", panel, sub, tc.panel, tc.sub)
			}
		})
	}
}
