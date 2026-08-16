package network

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hasan1808/pro-ui/logger"
)

// certCheckInterval bounds how often a handshake is allowed to touch the
// filesystem. Renewals happen on the order of days, so this only decides how
// long an operator waits after dropping in a certificate by hand.
const certCheckInterval = 10 * time.Second

// certIdentity is what the pair looked like on disk when it was last read.
// Hashing the contents would be exact, but it would mean reading both files on
// every check, which is the cost the throttle exists to avoid.
type certIdentity struct {
	certSize int64
	certMod  time.Time
	keySize  int64
	keyMod   time.Time
}

func (id certIdentity) same(other certIdentity) bool {
	return id.certSize == other.certSize && id.keySize == other.keySize &&
		id.certMod.Equal(other.certMod) && id.keyMod.Equal(other.keyMod)
}

// CertReloader serves a TLS certificate that can be replaced on disk while the
// listener stays up. The panel process is the parent of every VPN daemon
// (Xray, openvpn, xl2tpd, pptpd, ocserv, accel-ppp, charon, telemt), so
// restarting it to pick up a renewed certificate drops every connected VPN
// user. With short-lived certificates that renew every few days, that would be
// a recurring outage rather than a one-off.
type CertReloader struct {
	certFile string
	keyFile  string

	// The per-handshake path loads this pointer and nothing else.
	current atomic.Pointer[tls.Certificate]

	// Unix nanos of the earliest next stat, read without the mutex so a
	// handshake inside the throttle window touches only this word.
	nextCheck atomic.Int64

	// Held only while a reload runs, and never waited on: a handshake that
	// finds it taken serves the certificate it already has instead of queueing
	// behind somebody else's disk read.
	reloadMu sync.Mutex
	seen     certIdentity // guarded by reloadMu
	lastWarn string       // guarded by reloadMu

	// Test seams. Both are written once, before the reloader is handed to a
	// listener, so the read path needs no synchronisation for them.
	interval time.Duration
	now      func() time.Time
}

// NewCertReloader loads the pair once and returns the load error verbatim, so
// callers keep whatever they already do when a certificate will not load.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	r := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
		interval: certCheckInterval,
		now:      time.Now,
	}
	cert, err := loadCertPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	r.current.Store(cert)
	// A stat failure here is not fatal: the pair clearly loaded, and a zero
	// identity just means the first check reloads it once.
	r.seen, _ = statCertPair(certFile, keyFile)
	r.nextCheck.Store(r.now().Add(r.interval).UnixNano())
	return r, nil
}

// GetCertificate implements tls.Config.GetCertificate. It runs once per
// handshake, concurrently, on every accepting goroutine.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.maybeReload()
	if cert := r.current.Load(); cert != nil {
		return cert, nil
	}
	return nil, errors.New("no TLS certificate loaded")
}

func (r *CertReloader) maybeReload() {
	now := r.now()
	if now.UnixNano() < r.nextCheck.Load() {
		return
	}
	if !r.reloadMu.TryLock() {
		return
	}
	defer r.reloadMu.Unlock()

	// Re-arm before doing any work: a failing stat or a failing load must not
	// leave every following handshake making another filesystem round trip.
	r.nextCheck.Store(now.Add(r.interval).UnixNano())

	id, err := statCertPair(r.certFile, r.keyFile)
	if err != nil {
		r.warn(fmt.Sprint("Certificate reload: ", err, ", keeping the certificate already loaded"))
		return
	}
	if id.same(r.seen) {
		return
	}
	// Recorded even when the load below fails, so a pair that is broken for
	// good is not re-read every interval. acme.sh writes the certificate and
	// the key as two separate files, so a check can land between the two writes
	// and see a mismatched pair; that case still recovers, because the second
	// write changes the identity again.
	r.seen = id

	cert, err := loadCertPair(r.certFile, r.keyFile)
	if err != nil {
		r.warn(fmt.Sprint("Certificate reload failed: ", err, ", keeping the certificate already loaded"))
		return
	}
	r.current.Store(cert)
	r.lastWarn = ""
	logger.Info("Reloaded TLS certificate from", r.certFile)
}

// warn drops a repeat of the message it logged last. A certificate that stays
// broken would otherwise log on every check, forever.
func (r *CertReloader) warn(msg string) {
	if msg == r.lastWarn {
		return
	}
	r.lastWarn = msg
	logger.Warning(msg)
}

func loadCertPair(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	if err := checkKeyMatchesLeaf(&cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

// checkKeyMatchesLeaf re-checks what crypto/tls already checks on load.
// Swapping in a certificate whose key does not match it kills every subsequent
// handshake, and the window in which such a pair exists on disk is exactly the
// window this file exists for, so the guarantee is worth owning here rather
// than inheriting from an implementation detail of another package.
func checkKeyMatchesLeaf(cert *tls.Certificate) error {
	leaf := cert.Leaf
	if leaf == nil {
		if len(cert.Certificate) == 0 {
			return errors.New("certificate file contains no certificate")
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		// Kept so the handshake path never reparses the leaf.
		cert.Leaf = parsed
		leaf = parsed
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key of type %T cannot sign", cert.PrivateKey)
	}
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("unsupported certificate public key type %T", leaf.PublicKey)
	}
	if !pub.Equal(signer.Public()) {
		return errors.New("private key does not match the certificate")
	}
	return nil
}

func statCertPair(certFile, keyFile string) (certIdentity, error) {
	certInfo, err := os.Stat(certFile)
	if err != nil {
		return certIdentity{}, err
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		return certIdentity{}, err
	}
	return certIdentity{
		certSize: certInfo.Size(),
		certMod:  certInfo.ModTime(),
		keySize:  keyInfo.Size(),
		keyMod:   keyInfo.ModTime(),
	}, nil
}
