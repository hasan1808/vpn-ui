package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/logger"
)

// Certificates this panel is serving but does not manage, and how to take them over.
//
// deploy.sh and the vpn-ui menu have their own real-SSL path (vpn-ui.sh's
// obtain_letsencrypt_cert). It predates the certificate store and works completely
// outside it: acme.sh runs from $HOME/.acme.sh, installs the pair to
// <exe dir>/cert/{fullchain.pem,privkey.pem}, points the panel there with
// `vpn-ui cert`, and leaves acme.sh's OWN cron to renew it. Everything works, and
// the SSL page reports "the panel is NOT using the managed certificate", because
// strictly it is not.
//
// Two schedulers and two stores is the actual hazard. Adoption collapses them:
//
//   - the material is staged into the managed store, so the panel serves it from a
//     stable path that survives every future renewal
//   - acme.sh's PER-DOMAIN state is copied into that profile's own acme home, so
//     `--renew -d <primary>` works there. Without this the panel could show the
//     certificate but never renew it, which is worse than not adopting at all
//   - whichever settings named the old path are re-pointed at the stable one
//
// What adoption deliberately does NOT do is touch the operator's crontab. Removing
// acme.sh's cron is a separate, explicit action (StopLegacyRenewal), because the
// same cron may still be renewing domains that were never adopted.

// sslLegacyPairName is what vpn-ui.sh's --install-cert writes.
const (
	sslLegacyCertName = "fullchain.pem"
	sslLegacyKeyName  = "privkey.pem"
)

// SSLAdoptable is one certificate on disk that the manager could take over.
type SSLAdoptable struct {
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`

	// Source says where it came from, in words, so the card can explain itself.
	Source string `json:"source"`

	// SuggestedName is the profile slug adoption would use by default.
	SuggestedName string `json:"suggestedName"`

	// UsedByPanel / UsedBySub: adopting one a listener already serves is the common
	// case and re-points that listener; adopting one nothing serves just files it.
	UsedByPanel bool `json:"usedByPanel"`
	UsedBySub   bool `json:"usedBySub"`

	// HasAcmeState reports whether the legacy acme home holds renewal state for
	// this certificate. False means adoption can carry the material but not the
	// ability to renew it, and the UI has to say so.
	HasAcmeState bool `json:"hasAcmeState"`

	Info *SSLCertInfo `json:"info,omitempty"`
}

// sslLegacyAcmeHome is where the shell flow keeps acme.sh. Same expression
// sslacme.go's adoptLegacyAccount uses.
func sslLegacyAcmeHome() string {
	return filepath.Join(sslHomeDir(), ".acme.sh")
}

// sslManagedRoots is every directory a managed profile lives under, so a candidate
// already inside one is never offered for adoption.
//
// Resolved from the filesystem, never through ListSSLProfiles: that one reads the
// settings table to say which listener serves what, and containment must not depend
// on a database being up.
func sslManagedRoots() []string {
	names := SSLProfileNames()
	roots := make([]string, 0, len(names))
	for _, name := range names {
		if root, err := SSLProfileRoot(name); err == nil {
			roots = append(roots, root)
		}
	}
	return roots
}

func sslInsideManagedStore(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range sslManagedRoots() {
		rel, err := filepath.Rel(filepath.Clean(root), clean)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// DetectAdoptableCertificates lists usable pairs on disk that no managed profile
// owns: whatever the two listeners currently point at, plus the legacy shell flow's
// landing spot even when nothing is pointed at it yet.
//
// A pair that does not parse is skipped silently rather than offered: the card would
// promise something adoption is going to refuse anyway.
func DetectAdoptableCertificates() []SSLAdoptable {
	var ss SettingService
	panelCert, _ := ss.GetCertFile()
	panelKey, _ := ss.GetKeyFile()
	subCert, _ := ss.GetSubCertFile()
	subKey, _ := ss.GetSubKeyFile()

	certDir := filepath.Join(config.GetDBFolderPath(), "cert")

	type candidate struct{ cert, key, source string }
	candidates := []candidate{
		{panelCert, panelKey, "in use by the panel, issued outside the manager"},
		{subCert, subKey, "in use by the subscription server, issued outside the manager"},
		{
			filepath.Join(certDir, sslLegacyCertName),
			filepath.Join(certDir, sslLegacyKeyName),
			"installed by deploy.sh / the vpn-ui menu",
		},
	}

	// Certificates a profile already holds. Adoption COPIES the material, so the
	// original file stays where it was; without this the certificate an operator
	// just adopted would come straight back as something to adopt.
	adopted := make(map[string]bool)
	for _, p := range ListSSLProfiles() {
		if p.Active != nil {
			adopted[sslCertIdentity(p.Active)] = true
		}
	}

	seen := make(map[string]bool)
	var out []SSLAdoptable
	for _, c := range candidates {
		cert, key := strings.TrimSpace(c.cert), strings.TrimSpace(c.key)
		if cert == "" || key == "" || sslInsideManagedStore(cert) {
			continue
		}
		clean := filepath.Clean(cert)
		if seen[clean] {
			continue
		}
		seen[clean] = true

		info, err := InspectCertPair(cert, key)
		if err != nil || info == nil {
			continue
		}
		if adopted[sslCertIdentity(info)] {
			continue
		}
		out = append(out, SSLAdoptable{
			CertPath:      cert,
			KeyPath:       key,
			Source:        c.source,
			SuggestedName: SSLProfileNameFor(info.Identifiers),
			UsedByPanel:   samePath(panelCert, cert),
			UsedBySub:     samePath(subCert, cert),
			HasAcmeState:  sslLegacyAcmeStateDir(info.Identifiers) != "",
			Info:          info,
		})
	}
	return out
}

// sslCertIdentity is "the same certificate", for deciding whether a file on disk is
// one a profile already holds.
//
// Serial plus issuer, not the path and not the identifier set: a renewal for the same
// names is a DIFFERENT certificate and should be offered, while the same certificate
// reachable by two paths is one thing. Serials are only unique per issuer, hence both.
func sslCertIdentity(info *SSLCertInfo) string {
	if info == nil {
		return ""
	}
	return info.Issuer + "|" + info.Serial
}

// SSLProfileNameFor derives a profile slug from a certificate's own names, so an
// operator adopting one never has to invent a name for it.
//
// The slug rules are the strict ones NormalizeSSLProfile enforces, so a dotted host
// becomes panel-example-com. A name too long to fit keeps its readable head and
// takes a short hash of the full identifier so two long neighbours cannot collide.
func SSLProfileNameFor(identifiers []string) string {
	primary := ""
	if len(identifiers) > 0 {
		primary = strings.TrimSpace(identifiers[0])
	}
	if primary == "" {
		return "imported"
	}
	// A WILDCARD IS ITS OWN CERTIFICATE, and must not share a store with the bare
	// name. Every non-alphanumeric turns into a dash below and the leading run is
	// then trimmed, so "*.example.com" and "example.com" both slugged to
	// "example-com": issuing for one silently took over the other's store, moved
	// the active link, and re-pointed whatever listener was serving it. They are
	// separate certificates covering different names (a wildcard does NOT cover
	// the bare domain), so they get separate stores.
	// The hash below disambiguates names too long to slug, so it is taken over the
	// identifier AS GIVEN, asterisk included.
	original := primary
	wildcard := strings.HasPrefix(primary, "*.")
	if wildcard {
		primary = strings.TrimPrefix(primary, "*.")
	}
	var b strings.Builder
	if wildcard {
		b.WriteString("wildcard-")
	}
	for _, r := range strings.ToLower(primary) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "imported"
	}
	if len(slug) > 32 {
		sum := sha256.Sum256([]byte(original))
		slug = slug[:27] + "-" + hex.EncodeToString(sum[:2])
	}
	// "default" is the reserved profile at the original root; a wildcard cert whose
	// name happens to slug to it must not silently overwrite that store.
	if slug == SSLDefaultProfile {
		slug = "default-imported"
	}
	return slug
}

// sslLegacyAcmeStateDir returns the legacy acme.sh directory holding renewal state
// for these identifiers, or "" when there is none.
//
// acme.sh names the directory after the FIRST -d it was given, with an _ecc suffix
// for an EC key, which is why both spellings are probed.
func sslLegacyAcmeStateDir(identifiers []string) string {
	if len(identifiers) == 0 {
		return ""
	}
	primary := strings.TrimSpace(identifiers[0])
	if primary == "" {
		return ""
	}
	home := sslLegacyAcmeHome()
	for _, name := range []string{primary, primary + "_ecc"} {
		dir := filepath.Join(home, name)
		// The .conf is what --renew actually reads; a bare directory is not state.
		if st, err := os.Stat(filepath.Join(dir, primary+".conf")); err == nil && !st.IsDir() {
			return dir
		}
	}
	return ""
}

// SSLAdoptResult reports what adoption actually did, so the UI can say it rather
// than assume it.
type SSLAdoptResult struct {
	Profile     string `json:"profile"`
	CertPath    string `json:"certPath"`
	KeyPath     string `json:"keyPath"`
	CarriedAcme bool   `json:"carriedAcme"`
	Repointed   bool   `json:"repointed"`

	// LegacyCron is true when acme.sh's own cron is still installed, which means
	// two schedulers until the operator stops one.
	LegacyCron bool `json:"legacyCron"`
}

// AdoptCertificate takes an unmanaged pair into a managed profile.
//
// Ordering matters and is the same discipline the issue path uses: nothing is
// re-pointed until the material has been validated AND staged AND activated, so a
// failure anywhere leaves the panel serving exactly what it served before.
func (s *SSLService) AdoptCertificate(profile, certPath, keyPath string) (*SSLAdoptResult, error) {
	certPath, keyPath = strings.TrimSpace(certPath), strings.TrimSpace(keyPath)
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("both a certificate and a key path are required")
	}
	if sslInsideManagedStore(certPath) {
		return nil, fmt.Errorf("%s is already inside the certificate store", certPath)
	}

	info, err := InspectCertPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("that certificate could not be read: %w", err)
	}
	if !info.KeyMatchesLeaf {
		return nil, fmt.Errorf("the key at %s does not match the certificate at %s", keyPath, certPath)
	}

	if strings.TrimSpace(profile) == "" {
		profile = SSLProfileNameFor(info.Identifiers)
	}
	profile, root, err := sslResolveProfile(profile)
	if err != nil {
		return nil, err
	}
	store, err := OpenSSLStore(root)
	if err != nil {
		return nil, err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", keyPath, err)
	}

	version, err := store.Stage(SSLIdentifierSetKey(info.Identifiers), certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if err := store.Activate(version); err != nil {
		return nil, err
	}

	result := &SSLAdoptResult{
		Profile:  profile,
		CertPath: store.ActiveCertPath(),
		KeyPath:  store.ActiveKeyPath(),
	}

	// Carry the ability to RENEW, not just the bytes. Without acme.sh's per-domain
	// state in this profile's own home, RenewIfDue would find the certificate due
	// and acme.sh would have no record of it to renew.
	result.CarriedAcme = carryLegacyAcmeState(info.Identifiers, root)

	// Re-point only the listeners that were serving the old path. One that was on a
	// different certificate keeps it: adoption is not an assignment.
	var ss SettingService
	if p, err := ss.GetCertFile(); err == nil && samePath(p, certPath) {
		if err := ss.SetCertFile(result.CertPath); err == nil {
			_ = ss.SetKeyFile(result.KeyPath)
			result.Repointed = true
		}
	}
	if p, err := ss.GetSubCertFile(); err == nil && samePath(p, certPath) {
		if err := ss.SetSubCertFile(result.CertPath); err == nil {
			_ = ss.SetSubKeyFile(result.KeyPath)
			result.Repointed = true
		}
	}

	result.LegacyCron = SSLLegacyRenewalInstalled()
	return result, nil
}

// carryLegacyAcmeState copies acme.sh's per-domain renewal state out of the legacy
// home and into this profile's own, best effort.
//
// Best effort on purpose: the material has already been adopted by the time this
// runs, and failing the whole operation because a directory could not be copied
// would leave the operator worse off than the partial success. The return value is
// what the UI reports, so a false is visible rather than silent.
func carryLegacyAcmeState(identifiers []string, storeRoot string) bool {
	src := sslLegacyAcmeStateDir(identifiers)
	if src == "" {
		return false
	}
	dst := filepath.Join(SSLAcmeHome(storeRoot), filepath.Base(src))
	if _, err := os.Stat(dst); err == nil {
		// Already there. Overwriting would replace state this profile may have
		// issued itself, which is newer than anything the legacy home holds.
		return true
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		logger.Warning("ssl: preparing the acme home for an adopted certificate:", err)
		return false
	}
	if err := sslCopyTree(src, dst); err != nil {
		logger.Warning("ssl: copying acme.sh renewal state for an adopted certificate:", err)
		return false
	}
	return true
}

// sslCopyTree copies a directory of files one level deep, which is the shape of an
// acme.sh per-domain directory (conf, key, cer, csr; no subdirectories).
func sslCopyTree(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := sslCopyPath(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// SSLLegacyRenewalInstalled reports whether acme.sh's own cron entry is still there.
//
// Two schedulers is the state worth naming: the panel's job renews into the store
// while acme.sh's cron renews into the old path, and whichever the listeners are NOT
// pointed at is doing nothing but spending rate limit.
func SSLLegacyRenewalInstalled() bool {
	out, err := exec.Command("crontab", "-l").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), ".acme.sh")
}

// StopLegacyRenewal removes acme.sh's own cron entry, leaving the panel's job as the
// only scheduler.
//
// Separate from adoption and never automatic: that one cron renews EVERY domain in
// the legacy home, so removing it strands any that were not adopted. The caller is
// expected to have been told that.
func StopLegacyRenewal() error {
	acme := filepath.Join(sslLegacyAcmeHome(), "acme.sh")
	if _, err := os.Stat(acme); err != nil {
		return fmt.Errorf("there is no acme.sh at %s to stop", acme)
	}
	out, err := exec.Command(acme, "--uninstall-cronjob", "--home", sslLegacyAcmeHome()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("removing acme.sh's cron entry: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if SSLLegacyRenewalInstalled() {
		return fmt.Errorf("acme.sh reported success but its cron entry is still installed")
	}
	return nil
}
