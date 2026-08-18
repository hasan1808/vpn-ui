package service

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/config"
)

// The managed certificate store.
//
// webCertFile/webKeyFile point at a STABLE pair of paths inside this store that
// never change once set, so switching certificates or picking up a renewal never
// means rewriting a setting and never means restarting. That matters more here
// than in a normal web app: the panel process is the parent of every VPN daemon
// (see web/network/cert_reloader.go), so a restart to reload a certificate drops
// every connected VPN user, and a 160-hour Let's Encrypt IP certificate renews
// every few days.
//
// The stable path is a SYMLINK to an immutable version directory. Two properties
// make that work:
//
//   - web/network/cert_reloader.go stats the pair with os.Stat, which FOLLOWS
//     symlinks, so re-pointing the link changes the size+mtime it observes and the
//     running listener swaps within its 10s check interval, with no restart.
//   - Repointing is a single rename(2) of the link itself, so the cert and the key
//     switch together. Symlinking the two FILES separately would leave a window in
//     which fullchain.pem came from one issuance and privkey.pem from another.
//
// Versions are immutable and never written in place: an install lands in a fresh
// directory that nothing points at yet, so the directory the active link resolves
// to is never mid-write. Rollback is then just re-pointing the link at an older
// version.
//
// THE INVARIANT this file exists to hold: the active link never resolves to a pair
// that has not been loaded and key-matched first. At runtime a broken pair is
// survivable, because the reloader keeps serving the last good certificate
// (cert_reloader.go:126-131). At STARTUP there is no last good certificate and
// web/web.go:541-556 logs one line and silently comes up on plain HTTP instead.
// That silent downgrade, not a failed handshake, is the hazard worth this design.

const (
	// sslActiveLink is the name of the symlink webCertFile/webKeyFile resolve
	// through. Fixed, because its whole value is that it never changes.
	sslActiveLink = "active"

	// sslCertFileName / sslKeyFileName are the names inside every version dir.
	// "fullchain" is deliberate: a leaf alone makes clients that do not fetch
	// intermediates (stock Windows, which is exactly who the SSTP path serves)
	// fail to build a chain.
	sslCertFileName = "fullchain.pem"
	sslKeyFileName  = "privkey.pem"

	sslVersionsDir = "versions"
	sslScratchDir  = "scratch"

	// sslKeepVersions is how many superseded versions of one identifier set are
	// kept for rollback. A 160-hour certificate renewing on schedule produces
	// roughly 78 versions a year, so without a cap the store grows without bound.
	sslKeepVersions = 5
)

// SSLStore is a directory of certificate versions plus the active symlink.
// Safe for concurrent use only in the sense that each operation is individually
// atomic. Serialising ISSUANCE is the job of the issuance lock (sslacme.go), not
// of this type.
type SSLStore struct {
	root string
}

// DefaultSSLStoreRoot is the store next to the binary, under the same "cert"
// directory the self-signed panel certificate already uses (main.go:1746) and that
// uninstall.go:384-386 already removes. Putting it there means an uninstall cleans
// it up with everything else and a moved install carries it along, matching how
// config.GetDBFolderPath treats the database.
func DefaultSSLStoreRoot() string {
	return filepath.Join(config.GetDBFolderPath(), "cert", "managed")
}

// OpenSSLStore creates the store layout if it is missing and returns a handle.
func OpenSSLStore(root string) (*SSLStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("ssl store: empty root path")
	}
	s := &SSLStore{root: root}
	for _, d := range []string{root, filepath.Join(root, sslVersionsDir), filepath.Join(root, sslScratchDir)} {
		// 0700: the store holds private keys. The individual key files are 0600
		// as well, but a mode on the directory is what stops a world-readable
		// umask from mattering on a file we did not write ourselves (acme.sh
		// writes into the scratch dir).
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("ssl store: create %s: %w", d, err)
		}
	}
	return s, nil
}

// Root is the store's base directory.
func (s *SSLStore) Root() string { return s.root }

// ActiveCertPath and ActiveKeyPath are what webCertFile/webKeyFile are set to.
// They resolve through the active symlink, so they stay correct across every
// renewal and every switch between identifier sets.
func (s *SSLStore) ActiveCertPath() string {
	return filepath.Join(s.root, sslActiveLink, sslCertFileName)
}

func (s *SSLStore) ActiveKeyPath() string {
	return filepath.Join(s.root, sslActiveLink, sslKeyFileName)
}

// HasActive reports whether the active link resolves to a readable pair. It
// deliberately does not validate: callers that need validity call ActiveInfo.
func (s *SSLStore) HasActive() bool {
	if _, err := os.Stat(s.ActiveCertPath()); err != nil {
		return false
	}
	_, err := os.Stat(s.ActiveKeyPath())
	return err == nil
}

// ActiveVersion returns the version directory the active link currently resolves
// to, or "" when nothing is active.
func (s *SSLStore) ActiveVersion() string {
	target, err := os.Readlink(filepath.Join(s.root, sslActiveLink))
	if err != nil {
		return ""
	}
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(s.root, target)
}

// Stage writes a certificate/key pair into a NEW immutable version directory for
// the given identifier set, but only after the pair loads and the key matches the
// leaf. It never touches the active link, so a caller can stage freely without
// risking the running listener. Returns the version directory to hand to Activate.
func (s *SSLStore) Stage(setKey string, certPEM, keyPEM []byte) (string, error) {
	if len(certPEM) == 0 {
		return "", errors.New("ssl store: empty certificate")
	}
	if len(keyPEM) == 0 {
		return "", errors.New("ssl store: empty private key")
	}

	tmp, err := os.MkdirTemp(filepath.Join(s.root, sslScratchDir), "stage-")
	if err != nil {
		return "", fmt.Errorf("ssl store: stage dir: %w", err)
	}
	// Only removed on the failure paths below. On success the directory is
	// renamed away and no longer exists under this name.
	defer os.RemoveAll(tmp)

	certPath := filepath.Join(tmp, sslCertFileName)
	keyPath := filepath.Join(tmp, sslKeyFileName)
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", fmt.Errorf("ssl store: write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", fmt.Errorf("ssl store: write private key: %w", err)
	}

	// The gate. Everything downstream assumes a version directory holds a pair
	// that works, so this is the only place that assumption is established.
	if _, err := sslValidatePair(certPath, keyPath); err != nil {
		return "", fmt.Errorf("ssl store: refusing to store an unusable pair: %w", err)
	}

	setDir := filepath.Join(s.root, sslVersionsDir, sslSetDirName(setKey))
	if err := os.MkdirAll(setDir, 0o700); err != nil {
		return "", fmt.Errorf("ssl store: create set dir: %w", err)
	}
	version := filepath.Join(setDir, sslVersionStamp())
	// The target cannot exist: the stamp carries a random suffix precisely so two
	// installs in the same second do not collide, and rename onto an existing
	// non-empty directory would fail with ENOTEMPTY rather than silently merge.
	if err := os.Rename(tmp, version); err != nil {
		return "", fmt.Errorf("ssl store: publish version: %w", err)
	}
	return version, nil
}

// StageFromFiles is Stage for a pair acme.sh has just written into a scratch
// directory.
func (s *SSLStore) StageFromFiles(setKey, certPath, keyPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("ssl store: read issued certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("ssl store: read issued key: %w", err)
	}
	return s.Stage(setKey, certPEM, keyPEM)
}

// Activate points the stable path at a version directory, atomically.
//
// It re-validates rather than trusting that Stage did, because Activate is also
// the rollback entry point and the version being rolled back to may have been on
// disk for weeks. Cheap insurance against the one failure mode (a broken pair
// active at startup) that has no recovery path.
//
// A Let's Encrypt STAGING certificate is refused outright and there is no bypass.
// Staging exists to prove the ACME plumbing works, and its roots ("(STAGING)
// Pretend Pear X1" and friends) are in no trust store, so activating one would
// take the panel down for every browser while looking like a successful issuance.
func (s *SSLStore) Activate(version string) error {
	certPath := filepath.Join(version, sslCertFileName)
	keyPath := filepath.Join(version, sslKeyFileName)
	cert, err := sslValidatePair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("ssl store: refusing to activate: %w", err)
	}
	if sslIsStagingIssuer(cert.Leaf) {
		return fmt.Errorf("ssl store: refusing to activate a Let's Encrypt STAGING certificate (issuer %q): no browser trusts it, re-issue against production", cert.Leaf.Issuer.CommonName)
	}

	link := filepath.Join(s.root, sslActiveLink)
	// A real directory here is not something this code ever creates, so it means
	// something else did. Renaming a symlink onto a directory fails with EISDIR,
	// and the resulting error names neither the file nor the cause.
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("ssl store: %s exists and is not a symlink; move it aside", link)
	}

	// Relative, so the whole store can be copied or the install moved without the
	// link dangling. Absolute would bake in the current install path.
	target, err := filepath.Rel(s.root, version)
	if err != nil {
		return fmt.Errorf("ssl store: version %q is outside the store: %w", version, err)
	}

	// The reloader decides "changed" from size+mtime, so re-activating a version
	// whose two files happen to match the loaded ones byte for byte and stamp for
	// stamp would be invisible to it. Cheap to make impossible.
	now := time.Now()
	_ = os.Chtimes(certPath, now, now)
	_ = os.Chtimes(keyPath, now, now)

	tmpLink := filepath.Join(s.root, fmt.Sprintf(".active.%d.tmp", now.UnixNano()))
	if err := os.Symlink(target, tmpLink); err != nil {
		return fmt.Errorf("ssl store: create link: %w", err)
	}
	// The swap. rename(2) over an existing symlink replaces it atomically, so no
	// observer ever sees the active path missing or half-updated.
	if err := os.Rename(tmpLink, link); err != nil {
		_ = os.Remove(tmpLink)
		return fmt.Errorf("ssl store: swap link: %w", err)
	}
	s.pruneVersions(filepath.Dir(version))
	return nil
}

// Versions lists a set's version directories, newest first. The stamp sorts
// lexically in time order, which is why it is formatted the way it is.
func (s *SSLStore) Versions(setKey string) []string {
	setDir := filepath.Join(s.root, sslVersionsDir, sslSetDirName(setKey))
	entries, err := os.ReadDir(setDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(setDir, e.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

// pruneVersions drops all but the newest sslKeepVersions of a set, and never the
// one the active link resolves to (which can be an older version after a
// rollback).
func (s *SSLStore) pruneVersions(setDir string) {
	entries, err := os.ReadDir(setDir)
	if err != nil {
		return
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(setDir, e.Name()))
		}
	}
	if len(dirs) <= sslKeepVersions {
		return
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	active := s.ActiveVersion()
	for _, d := range dirs[sslKeepVersions:] {
		if d == active {
			continue
		}
		_ = os.RemoveAll(d)
	}
}

// ActiveInfo describes whatever the stable path currently resolves to.
func (s *SSLStore) ActiveInfo() (*SSLCertInfo, error) {
	return InspectCertPair(s.ActiveCertPath(), s.ActiveKeyPath())
}

// SSLCertInfo is everything the UI needs to say about a certificate without
// parsing PEM itself.
type SSLCertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	Serial       string    `json:"serial"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	Identifiers  []string  `json:"identifiers"` // every SAN, DNS names and IPs together
	DNSNames     []string  `json:"dnsNames"`
	IPAddresses  []string  `json:"ipAddresses"`
	KeyAlgorithm string    `json:"keyAlgorithm"` // RSA, ECDSA, Ed25519
	KeyBits      int       `json:"keyBits"`

	// ChainLength counts every certificate in the file, leaf included.
	// HasIntermediates is the one that matters: a leaf on its own makes clients
	// that will not fetch an issuer (stock Windows, i.e. the SSTP and IKEv2
	// audience) fail to build a chain, and the failure they report says nothing
	// about a missing intermediate.
	ChainLength      int  `json:"chainLength"`
	HasIntermediates bool `json:"hasIntermediates"`
	SelfSigned       bool `json:"selfSigned"`

	// Staging marks a Let's Encrypt staging certificate. Never activatable.
	Staging bool `json:"staging"`

	// Lifetime and Remaining are Go durations, which encoding/json renders as
	// NANOSECONDS, not seconds. LifetimeText and RemainingText are the same values
	// already formatted, so the UI never has to divide by 1e9 and never has to
	// reimplement the "4d2h" rendering the error messages already use.
	Lifetime      time.Duration `json:"lifetimeNanos"`
	Remaining     time.Duration `json:"remainingNanos"`
	LifetimeText  string        `json:"lifetimeText"`
	RemainingText string        `json:"remainingText"`

	Expired        bool      `json:"expired"`
	RenewalDue     bool      `json:"renewalDue"`
	RenewalDueAt   time.Time `json:"renewalDueAt"`
	KeyMatchesLeaf bool      `json:"keyMatchesLeaf"`
}

// InspectCertPair parses a pair on disk. A key that does not match the leaf is
// reported in KeyMatchesLeaf rather than returned as an error, so the UI can show
// the operator WHAT is wrong with a pair they pointed at instead of just refusing.
func InspectCertPair(certPath, keyPath string) (*SSLCertInfo, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", certPath, err)
	}
	info, err := describeChainPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if _, err := sslValidatePair(certPath, keyPath); err == nil {
		info.KeyMatchesLeaf = true
	}
	return info, nil
}

// describeChainPEM parses a PEM bundle and describes its leaf.
func describeChainPEM(certPEM []byte) (*SSLCertInfo, error) {
	chain, err := sslParseChain(certPEM)
	if err != nil {
		return nil, err
	}
	leaf := chain[0]

	info := &SSLCertInfo{
		Subject:     leaf.Subject.CommonName,
		Issuer:      sslIssuerName(leaf),
		Serial:      leaf.SerialNumber.String(),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		DNSNames:    append([]string(nil), leaf.DNSNames...),
		ChainLength: len(chain),
		SelfSigned:  isSelfSigned(leaf),
		Staging:     sslIsStagingIssuer(leaf),
	}
	for _, ip := range leaf.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	info.Identifiers = append(append([]string(nil), info.DNSNames...), info.IPAddresses...)
	sort.Strings(info.Identifiers)

	// Every non-leaf that is not a self-signed root is an intermediate the server
	// has to send itself.
	for _, c := range chain[1:] {
		if !isSelfSigned(c) {
			info.HasIntermediates = true
			break
		}
	}

	info.KeyAlgorithm, info.KeyBits = sslKeyDescription(leaf.PublicKey)
	info.Lifetime = leaf.NotAfter.Sub(leaf.NotBefore)
	info.Remaining = time.Until(leaf.NotAfter)
	info.LifetimeText = sslFormatDuration(info.Lifetime)
	info.RemainingText = sslFormatDuration(info.Remaining)
	info.Expired = info.Remaining <= 0
	info.RenewalDueAt = sslRenewalDueAt(leaf)
	info.RenewalDue = !time.Now().Before(info.RenewalDueAt)
	return info, nil
}

// sslRenewalDueAt is when a certificate should be renewed, derived from its own
// lifetime rather than from a fixed number of days.
//
// A third of the lifetime before expiry. On a 90-day certificate that is 30 days
// out, which is exactly acme.sh's own default (DEFAULT_RENEW=60 means renew at day
// 60 of 90). On a 160-hour Let's Encrypt IP certificate it is 53 hours out, i.e.
// at about 4.5 days of age, which is where `--days -2` puts it too (see
// sslacme.go). One rule, and the two schedules it has to agree with both fall out
// of it.
func sslRenewalDueAt(leaf *x509.Certificate) time.Time {
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime <= 0 {
		return leaf.NotAfter
	}
	return leaf.NotAfter.Add(-lifetime / 3)
}

// sslMinRenewalAge is the floor this panel enforces on its own, independent of
// what acme.sh believes. A backstop against a bad --days value or a cron firing
// far more often than intended: either of those turns into new-certificate
// requests, and the exact-set limit that governs them (5 per 7 days, one slot back
// every 34 hours) is the one with a days-long lockout and no override form.
//
// A quarter of the lifetime, which for a 160-hour IP certificate is 40 hours. That
// is comfortably below any legitimate renewal (a third of the lifetime BEFORE
// expiry is three quarters of the way through it) so this never blocks the normal
// schedule, and comfortably above a runaway cron. Deriving it from the lifetime
// rather than hardcoding hours keeps it sane for a 90-day certificate too.
func sslMinRenewalAge(lifetime time.Duration) time.Duration {
	const floor = time.Hour
	age := lifetime / 4
	if age < floor {
		return floor
	}
	return age
}

// ValidateCertPair reports whether a certificate/key pair on disk is usable as a
// TLS server identity. Exported for the CLI, which stores certificate paths
// without going through the settings form and so misses the validation
// AllSetting.CheckValid does (entity.go:140-152).
func ValidateCertPair(certPath, keyPath string) error {
	_, err := sslValidatePair(certPath, keyPath)
	return err
}

// sslValidatePair is the single definition of "this pair is usable". It loads the
// pair exactly as the TLS listener will and then re-checks the key against the
// leaf.
//
// The second check duplicates one crypto/tls already performs on load. It is
// re-stated here on purpose: the guarantee that the active path never resolves to
// a mismatched pair is the entire point of this store, and inheriting it from an
// implementation detail of another package would make it silently removable.
// web/network/cert_reloader.go:163-189 owns the same check for the handshake path,
// for the same reason, and neither package imports the other.
func sslValidatePair(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		if len(cert.Certificate) == 0 {
			return nil, errors.New("certificate file contains no certificate")
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		cert.Leaf = parsed
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key of type %T cannot sign", cert.PrivateKey)
	}
	pub, ok := cert.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("unsupported certificate public key type %T", cert.Leaf.PublicKey)
	}
	if !pub.Equal(signer.Public()) {
		return nil, errors.New("private key does not match the certificate")
	}
	return &cert, nil
}

func sslParseChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate is not parseable: %w", err)
		}
		chain = append(chain, crt)
	}
	if len(chain) == 0 {
		return nil, errors.New("no certificate found in the file (is it PEM?)")
	}
	return chain, nil
}

func isSelfSigned(c *x509.Certificate) bool {
	return string(c.RawSubject) == string(c.RawIssuer)
}

// sslIssuerName is who signed this certificate, in the words an operator
// recognises.
//
// ORGANISATION FIRST, and that ordering is the whole point. A CA's intermediate
// carries the brand in the Organization and a bare code in the CommonName: Let's
// Encrypt's Generation Y intermediates (live since November 2025) are named
// YE1..YE3 and YR1..YR3, and the ones before them R10, R11, E5, E6. Preferring
// the CommonName made the panel report a certificate as issued by "YR1", which
// identifies nothing to the person reading it and looks like a fault.
//
// The code is still worth showing, because which intermediate signed a
// certificate is exactly what matters when a client rejects the chain, so it
// comes along in parentheses rather than being dropped.
func sslIssuerName(c *x509.Certificate) string {
	cn := strings.TrimSpace(c.Issuer.CommonName)
	var org string
	if len(c.Issuer.Organization) > 0 {
		org = strings.TrimSpace(c.Issuer.Organization[0])
	}
	switch {
	case org != "" && cn != "" && !strings.EqualFold(org, cn):
		return org + " (" + cn + ")"
	case org != "":
		return org
	case cn != "":
		return cn
	}
	return c.Issuer.String()
}

// sslIsStagingIssuer spots a Let's Encrypt staging certificate. Their whole
// hierarchy is deliberately named with a "(STAGING)" prefix ("(STAGING) Pretend
// Pear X1", "(STAGING) Artificial Apricot R3", "(STAGING) Let's Encrypt"), which
// is the only marker in the certificate itself that distinguishes staging from
// production, since everything else about it is well-formed.
func sslIsStagingIssuer(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	if strings.Contains(strings.ToUpper(c.Issuer.CommonName), "(STAGING)") {
		return true
	}
	for _, o := range c.Issuer.Organization {
		if strings.Contains(strings.ToUpper(o), "(STAGING)") {
			return true
		}
	}
	return false
}

func sslKeyDescription(pub any) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return fmt.Sprintf("%T", pub), 0
	}
}

// sslVersionStamp sorts lexically in time order (so a plain string sort is a
// chronological sort) and carries a random tail so two installs inside the same
// second cannot collide on a directory name.
func sslVersionStamp() string {
	var b [4]byte
	// A failed read here only costs uniqueness within one second, and the caller
	// would then get a rename error rather than a silent overwrite, so the error
	// is not worth propagating through every call site.
	_, _ = rand.Read(b[:])
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

// sslSetDirName turns an identifier set key into one filesystem-safe directory
// name. A readable prefix so an operator can tell the directories apart by eye,
// plus a hash of the FULL key so two different sets that share a first identifier
// (example.com versus example.com + www.example.com, which Let's Encrypt counts in
// completely separate buckets) never land in the same directory.
func sslSetDirName(setKey string) string {
	sum := sha256.Sum256([]byte(setKey))
	first := setKey
	if i := strings.IndexByte(first, ','); i >= 0 {
		first = first[:i]
	}
	prefix := sslSanitize(first)
	if len(prefix) > 40 {
		prefix = prefix[:40]
	}
	if prefix == "" {
		prefix = "set"
	}
	return prefix + "-" + hex.EncodeToString(sum[:4])
}

// sslSanitize keeps a string to characters that are unambiguous in a path.
// Wildcards ("*.example.com") and IPv6 colons both need this.
func sslSanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), ".")
}

// sslLocalIPs is the set of addresses actually configured on this host's
// interfaces, used by the preflight to answer "is this address mine".
func sslLocalIPs() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out = append(out, ipn.IP)
		}
	}
	return out, nil
}
