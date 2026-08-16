package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/op/go-logging"
)

// The panel's logger is a package global that stays nil until InitLogger runs,
// and a reload logs. Point the file backend at a temporary directory so the run
// does not need /var/log/vpn-ui.
func TestMain(m *testing.M) {
	logDir, err := os.MkdirTemp("", "vpn-ui-cert-reload")
	if err == nil {
		os.Setenv("VPNUI_LOG_FOLDER", logDir)
	}
	logger.InitLogger(logging.WARNING)
	code := m.Run()
	logger.CloseLogger()
	if logDir != "" {
		os.RemoveAll(logDir)
	}
	os.Exit(code)
}

// testClock drives the reload throttle without spending wall clock time. It is
// atomic because the concurrency test advances it while handshakes read it.
type testClock struct {
	nanos atomic.Int64
}

func (c *testClock) Now() time.Time {
	return time.Unix(0, c.nanos.Load())
}

func (c *testClock) Advance(d time.Duration) {
	c.nanos.Add(int64(d))
}

type certPair struct {
	certPEM []byte
	keyPEM  []byte
	serial  *big.Int
}

func generateSelfSigned(t *testing.T, serial int64) certPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "vpn-ui cert reload test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return certPair{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		serial:  tmpl.SerialNumber,
	}
}

// writeFileAt pins the modification time so the identity check does not depend
// on the filesystem's timestamp resolution, and so a rewrite is detected even
// when the new file happens to be the same size as the old one.
func writeFileAt(t *testing.T, path string, data []byte, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// newTestReloader swaps in the fake clock the way the constructor would have
// used it, so the throttle can be crossed on demand.
func newTestReloader(t *testing.T, certFile, keyFile string) (*CertReloader, *testClock) {
	t.Helper()
	r, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	clock := &testClock{}
	clock.nanos.Store(time.Now().UnixNano())
	r.now = clock.Now
	r.nextCheck.Store(clock.Now().Add(r.interval).UnixNano())
	return r, clock
}

// serveTLS mirrors the listener chain both servers build: the auto-HTTPS
// redirect wrapper underneath, the TLS listener on top.
func serveTLS(t *testing.T, r *CertReloader) string {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := tls.NewListener(NewAutoHttpsListener(raw), &tls.Config{
		GetCertificate: r.GetCertificate,
	})
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					tlsConn.Handshake()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// lastWarning reads back what the reloader logged last. It is the in-process
// record of the "kept the previous certificate" path.
func lastWarning(r *CertReloader) string {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	return r.lastWarn
}

// handshakeSerial returns the serial number of the leaf the server served.
func handshakeSerial(t *testing.T, addr string) *big.Int {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		t.Fatal("server served no certificate")
	}
	return chain[0].SerialNumber
}

func TestCertReloaderServesRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "panel.crt")
	keyFile := filepath.Join(dir, "panel.key")

	first := generateSelfSigned(t, 1001)
	second := generateSelfSigned(t, 2002)
	third := generateSelfSigned(t, 3003)
	fourth := generateSelfSigned(t, 4004)

	mod := time.Now().Truncate(time.Second)
	writeFileAt(t, certFile, first.certPEM, mod)
	writeFileAt(t, keyFile, first.keyPEM, mod)

	r, clock := newTestReloader(t, certFile, keyFile)
	addr := serveTLS(t, r)

	got := handshakeSerial(t, addr)
	t.Logf("initial handshake served serial %s (expected %s)", got, first.serial)
	if got.Cmp(first.serial) != 0 {
		t.Fatalf("initial handshake served serial %s, want %s", got, first.serial)
	}

	// A renewal: both files replaced, exactly what acme.sh leaves behind.
	mod = mod.Add(time.Minute)
	writeFileAt(t, certFile, second.certPEM, mod)
	writeFileAt(t, keyFile, second.keyPEM, mod)

	// Inside the throttle window nothing is even stat'ed yet.
	got = handshakeSerial(t, addr)
	t.Logf("inside the throttle window served serial %s (expected the old %s)", got, first.serial)
	if got.Cmp(first.serial) != 0 {
		t.Fatalf("throttle window: served serial %s, want the previous %s", got, first.serial)
	}

	clock.Advance(certCheckInterval + time.Second)
	got = handshakeSerial(t, addr)
	t.Logf("after the throttle window served serial %s (expected the renewed %s)", got, second.serial)
	if got.Cmp(second.serial) != 0 {
		t.Fatalf("after renewal: served serial %s, want %s", got, second.serial)
	}

	// The dangerous window: acme.sh has written the new certificate but not yet
	// the matching key. The listener must not start serving that pair.
	mod = mod.Add(time.Minute)
	writeFileAt(t, certFile, third.certPEM, mod)
	clock.Advance(certCheckInterval + time.Second)

	got = handshakeSerial(t, addr)
	t.Logf("mismatched pair on disk served serial %s (expected the last good %s)", got, second.serial)
	if got.Cmp(second.serial) != 0 {
		t.Fatalf("mismatched pair: served serial %s, want the last good %s", got, second.serial)
	}
	if warn := lastWarning(r); warn == "" {
		t.Error("mismatched pair was rejected without logging a warning")
	} else {
		t.Logf("mismatched pair logged: %s", warn)
	}

	// The key lands a moment later and the pair matches again.
	mod = mod.Add(time.Minute)
	writeFileAt(t, keyFile, third.keyPEM, mod)
	clock.Advance(certCheckInterval + time.Second)

	got = handshakeSerial(t, addr)
	t.Logf("after the key landed served serial %s (expected %s)", got, third.serial)
	if got.Cmp(third.serial) != 0 {
		t.Fatalf("after the key landed: served serial %s, want %s", got, third.serial)
	}

	// An unreadable certificate file must not break the listener either.
	mod = mod.Add(time.Minute)
	writeFileAt(t, certFile, []byte("not a certificate"), mod)
	writeFileAt(t, keyFile, fourth.keyPEM, mod)
	clock.Advance(certCheckInterval + time.Second)

	got = handshakeSerial(t, addr)
	t.Logf("garbage certificate file served serial %s (expected the last good %s)", got, third.serial)
	if got.Cmp(third.serial) != 0 {
		t.Fatalf("garbage certificate: served serial %s, want the last good %s", got, third.serial)
	}
	if warn := lastWarning(r); warn == "" {
		t.Error("garbage certificate was rejected without logging a warning")
	} else {
		t.Logf("garbage certificate logged: %s", warn)
	}

	// Recovery after the bad write is repaired.
	mod = mod.Add(time.Minute)
	writeFileAt(t, certFile, fourth.certPEM, mod)
	clock.Advance(certCheckInterval + time.Second)

	got = handshakeSerial(t, addr)
	t.Logf("after recovery served serial %s (expected %s)", got, fourth.serial)
	if got.Cmp(fourth.serial) != 0 {
		t.Fatalf("after recovery: served serial %s, want %s", got, fourth.serial)
	}
}

func TestCertReloaderMissingFilesKeepListenerUp(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "panel.crt")
	keyFile := filepath.Join(dir, "panel.key")

	pair := generateSelfSigned(t, 5005)
	mod := time.Now().Truncate(time.Second)
	writeFileAt(t, certFile, pair.certPEM, mod)
	writeFileAt(t, keyFile, pair.keyPEM, mod)

	r, clock := newTestReloader(t, certFile, keyFile)
	addr := serveTLS(t, r)

	if err := os.Remove(certFile); err != nil {
		t.Fatalf("remove certificate: %v", err)
	}
	clock.Advance(certCheckInterval + time.Second)

	got := handshakeSerial(t, addr)
	t.Logf("certificate file deleted, still serving serial %s", got)
	if got.Cmp(pair.serial) != 0 {
		t.Fatalf("deleted certificate: served serial %s, want %s", got, pair.serial)
	}
}

func TestCertReloaderStartupFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "panel.crt")
	keyFile := filepath.Join(dir, "panel.key")

	// Both servers fall back to plain HTTP on this error, so it has to keep
	// coming back as an error rather than a half-built reloader.
	if _, err := NewCertReloader(certFile, keyFile); err == nil {
		t.Fatal("NewCertReloader accepted a missing certificate pair")
	}

	first := generateSelfSigned(t, 6006)
	second := generateSelfSigned(t, 7007)
	mod := time.Now().Truncate(time.Second)
	writeFileAt(t, certFile, first.certPEM, mod)
	writeFileAt(t, keyFile, second.keyPEM, mod)

	if _, err := NewCertReloader(certFile, keyFile); err == nil {
		t.Fatal("NewCertReloader accepted a key that does not match the certificate")
	}
}

// crypto/tls happens to reject a mismatched pair on load today, so cover the
// second check on its own rather than through a path that never reaches it.
func TestCheckKeyMatchesLeaf(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "panel.crt")
	keyFile := filepath.Join(dir, "panel.key")

	good := generateSelfSigned(t, 9001)
	other := generateSelfSigned(t, 9002)
	mod := time.Now().Truncate(time.Second)
	writeFileAt(t, certFile, good.certPEM, mod)
	writeFileAt(t, keyFile, good.keyPEM, mod)

	matching, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load matching pair: %v", err)
	}
	if err := checkKeyMatchesLeaf(&matching); err != nil {
		t.Fatalf("matching pair rejected: %v", err)
	}

	mismatched := matching
	otherKey, err := tls.X509KeyPair(other.certPEM, other.keyPEM)
	if err != nil {
		t.Fatalf("load second pair: %v", err)
	}
	mismatched.PrivateKey = otherKey.PrivateKey
	if err := checkKeyMatchesLeaf(&mismatched); err == nil {
		t.Fatal("a key from another pair was accepted")
	} else {
		t.Logf("mismatched key rejected: %v", err)
	}
}

func TestCertReloaderConcurrentGetCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "panel.crt")
	keyFile := filepath.Join(dir, "panel.key")

	pairs := []certPair{
		generateSelfSigned(t, 8001),
		generateSelfSigned(t, 8002),
		generateSelfSigned(t, 8003),
	}
	mod := time.Now().Truncate(time.Second)
	writeFileAt(t, certFile, pairs[0].certPEM, mod)
	writeFileAt(t, keyFile, pairs[0].keyPEM, mod)

	r, err := NewCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewCertReloader: %v", err)
	}
	// No throttle, so every one of these calls takes the reload path and the
	// contention this test is looking for is at its worst.
	r.interval = 0
	r.nextCheck.Store(0)

	valid := make(map[string]bool, len(pairs))
	for _, p := range pairs {
		valid[p.serial.String()] = true
	}

	done := make(chan struct{})
	var writers sync.WaitGroup
	for i := range 2 {
		writers.Add(1)
		go func(offset int) {
			defer writers.Done()
			for n := offset; ; n++ {
				select {
				case <-done:
					return
				default:
				}
				p := pairs[n%len(pairs)]
				// Deliberately not atomic: this is how acme.sh writes, and a
				// torn read is one of the states the reloader must survive.
				if err := os.WriteFile(certFile, p.certPEM, 0o600); err != nil {
					t.Errorf("write certificate: %v", err)
					return
				}
				if err := os.WriteFile(keyFile, p.keyPEM, 0o600); err != nil {
					t.Errorf("write key: %v", err)
					return
				}
			}
		}(i)
	}

	var readers sync.WaitGroup
	for range 32 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 500 {
				cert, err := r.GetCertificate(&tls.ClientHelloInfo{})
				if err != nil {
					t.Errorf("GetCertificate: %v", err)
					return
				}
				if cert == nil || cert.Leaf == nil {
					t.Error("GetCertificate returned no usable certificate")
					return
				}
				// Never a pair that was not written as a pair, whatever the
				// writers were in the middle of.
				if !valid[cert.Leaf.SerialNumber.String()] {
					t.Errorf("served unknown serial %s", cert.Leaf.SerialNumber)
					return
				}
				if err := checkKeyMatchesLeaf(cert); err != nil {
					t.Errorf("served a mismatched pair: %v", err)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(done)
	writers.Wait()
}
