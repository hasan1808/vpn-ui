package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hasan1808/pro-ui/config"
)

// Named certificates.
//
// One host routinely needs more than one certificate. The panel is reached on an
// admin name, subscriptions are handed to customers on a different one, and an
// operator may not want the two to share an identity at all: a subscription URL is
// public, the panel's hostname is not, and putting both names in one SAN list
// publishes the panel's to Certificate Transparency. Inbounds have their own reasons
// to differ again.
//
// The store already parameterises EVERYTHING on its root: the active link, the
// version tree, the acme home, the issuance lock and the ledger are all derived from
// it (sslstore.go, sslacme.go, sslledger.go). So a second certificate is just a
// second root, and a profile is a name for one. Nothing about issuance, staging,
// validation or the fan-out has to know profiles exist.
//
// The DEFAULT profile keeps the original root untouched. Existing installs already
// have webCertFile/subCertFile pointing into it, and moving those would break TLS on
// the next restart for no gain. Named profiles are SIBLINGS of it rather than
// children, so nothing that reads the default root can mistake one for a version,
// and uninstall's removal of the whole cert directory still cleans them all up.

// SSLDefaultProfile is the name of the profile stored at the original root. Empty
// means the same thing everywhere a name is accepted.
const SSLDefaultProfile = "default"

// sslProfilesDirName holds the named profiles, beside the default profile's root.
const sslProfilesDirName = "profiles"

// SSLProfilesRoot is the directory the named profiles live in.
func SSLProfilesRoot() string {
	return filepath.Join(config.GetDBFolderPath(), "cert", sslProfilesDirName)
}

// NormalizeSSLProfile resolves an incoming name to its canonical form, refusing one
// that could escape the profiles directory or collide with the default.
//
// The rules are tight on purpose: the name becomes a directory that holds private
// keys and is chosen over HTTP, so anything but a plain lowercase slug is rejected
// rather than sanitised. Sanitising would silently map two different requests onto
// one profile.
func NormalizeSSLProfile(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || name == SSLDefaultProfile {
		return SSLDefaultProfile, nil
	}
	if len(name) > 32 {
		return "", fmt.Errorf("certificate name %q is too long (32 characters max)", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return "", fmt.Errorf("certificate name %q may only use letters, digits, - and _", name)
		}
	}
	return name, nil
}

// SSLProfileRoot is the store root for a profile. The default profile keeps the
// original location so nothing an existing install already points at moves.
func SSLProfileRoot(name string) (string, error) {
	name, err := NormalizeSSLProfile(name)
	if err != nil {
		return "", err
	}
	if name == SSLDefaultProfile {
		return DefaultSSLStoreRoot(), nil
	}
	return filepath.Join(SSLProfilesRoot(), name), nil
}

// SSLProfileSummary is one certificate as the settings page lists them.
type SSLProfileSummary struct {
	Name      string `json:"name"`
	StoreRoot string `json:"storeRoot"`
	CertPath  string `json:"certPath"`
	KeyPath   string `json:"keyPath"`

	// Active is nil when the profile exists but holds no usable certificate yet.
	Active *SSLCertInfo `json:"active,omitempty"`

	// UsedByPanel / UsedBySub say which listener is currently serving THIS
	// profile, which is the question the page exists to answer.
	UsedByPanel bool `json:"usedByPanel"`
	UsedBySub   bool `json:"usedBySub"`

	// Nickname is the operator's own label for this certificate, empty by
	// default. It sits BESIDE the certificate's real names rather than replacing
	// them, so nothing it says can make a row ambiguous. See sslnickname.go.
	Nickname string `json:"nickname"`

	// AutoRenew reports whether the panel renews this one on its own. Absence of
	// the marker means yes, so every certificate that existed before the toggle
	// did keeps renewing. See sslautorenew.go.
	AutoRenew bool `json:"autoRenew"`
}

// ListSSLProfiles returns every profile that exists on disk, default first and the
// rest by name.
//
// The default profile is always listed even when its directory has never been
// created, because it is where a first issuance lands and an empty list would leave
// the page with nothing to select.
// SSLProfileNames is the profiles that exist, default first then the rest by name.
//
// Filesystem only, and deliberately so: a profile is a directory, and asking the
// settings table where the listeners point has nothing to do with which profiles
// exist. Keeping the two apart is what lets the containment check
// (sslInsideManagedStore) work with no database at all.
func SSLProfileNames() []string {
	names := []string{SSLDefaultProfile}
	entries, err := os.ReadDir(SSLProfilesRoot())
	if err != nil {
		return names
	}
	var named []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// A directory whose name this build would refuse is not a profile it can
		// operate on, so listing it would only offer a broken row.
		if n, err := NormalizeSSLProfile(e.Name()); err == nil && n != SSLDefaultProfile {
			named = append(named, n)
		}
	}
	sort.Strings(named)
	return append(names, named...)
}

func ListSSLProfiles() []SSLProfileSummary {
	names := SSLProfileNames()

	var ss SettingService
	panelCert, _ := ss.GetCertFile()
	subCert, _ := ss.GetSubCertFile()

	out := make([]SSLProfileSummary, 0, len(names))
	for _, name := range names {
		root, err := SSLProfileRoot(name)
		if err != nil {
			continue
		}
		summary := SSLProfileSummary{
			Name:      name,
			StoreRoot: root,
			CertPath:  filepath.Join(root, sslActiveLink, sslCertFileName),
			KeyPath:   filepath.Join(root, sslActiveLink, sslKeyFileName),
			AutoRenew: sslAutoRenewEnabledAt(root),
			Nickname:  sslNicknameAt(root),
		}
		// Read-only: opening the store would CREATE the layout, which would turn
		// listing into a side effect that resurrects a profile someone deleted.
		store := &SSLStore{root: root}
		if store.HasActive() {
			if info, err := store.ActiveInfo(); err == nil {
				summary.Active = info
			}
		}
		summary.UsedByPanel = samePath(panelCert, summary.CertPath)
		summary.UsedBySub = samePath(subCert, summary.CertPath)
		out = append(out, summary)
	}
	return out
}

// samePath compares two configured paths the way ListSSLConsumers does: on the
// cleaned string, not on where it resolves to. An empty setting matches nothing.
func samePath(a, b string) bool {
	if strings.TrimSpace(a) == "" {
		return false
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// SSLAssignTargetPanel / SSLAssignTargetSub name the listeners a profile can be
// assigned to. They are the only two: an inbound picks its certificate in its own
// form, by path, and rewriting inbound settings from here would silently change
// what a protocol serves.
const (
	SSLAssignTargetPanel = "panel"
	SSLAssignTargetSub   = "subscription"
)

// DeleteSSLProfile removes a named profile's whole store.
//
// Refuses while a listener still points at it: the setting would keep naming paths
// that no longer resolve, and web.go's startup then quietly falls back to plain
// HTTP, which is the exact silent downgrade the store design exists to prevent.
// The default profile is never deletable — it is where issuance lands.
func DeleteSSLProfile(name string) error {
	name, err := NormalizeSSLProfile(name)
	if err != nil {
		return err
	}
	if name == SSLDefaultProfile {
		return fmt.Errorf("the default certificate cannot be deleted")
	}
	root, err := SSLProfileRoot(name)
	if err != nil {
		return err
	}
	certPath := filepath.Join(root, sslActiveLink, sslCertFileName)

	var ss SettingService
	var inUse []string
	if p, err := ss.GetCertFile(); err == nil && samePath(p, certPath) {
		inUse = append(inUse, "the panel")
	}
	if p, err := ss.GetSubCertFile(); err == nil && samePath(p, certPath) {
		inUse = append(inUse, "the subscription server")
	}
	if consumers, err := ListSSLConsumers(certPath); err == nil {
		for _, c := range consumers {
			if c.Kind != SSLConsumerPanel && c.Kind != SSLConsumerSub {
				inUse = append(inUse, c.Label)
			}
		}
	}
	if len(inUse) > 0 {
		return fmt.Errorf("%q is still served by %s — point those at another certificate first",
			name, strings.Join(inUse, ", "))
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("removing certificate %q: %w", name, err)
	}
	return nil
}
