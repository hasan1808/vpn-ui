package service

import "strings"

// The certificate list an inbound picks from.
//
// WHY THIS EXISTS. Turning TLS on for an inbound used to mean typing two absolute
// filesystem paths, or pressing a button that filled in the PANEL's certificate
// whether or not that was the right one. An operator who had just obtained a
// certificate for a subscription hostname had no way to say "use that one" except
// to go and read its path off the SSL page.
//
// So the inbound form gets the same list the SSL manager shows, and choosing an
// entry writes the STABLE managed paths (.../active/fullchain.pem) rather than a
// version directory. That is what makes the choice survive: every renewal replaces
// what the active link points at, and the inbound keeps working without being
// edited again. A version path would pin the inbound to one certificate and break
// silently the first time it renewed.

// SSLCertificateChoice is one option in an inbound's certificate picker.
type SSLCertificateChoice struct {
	// Profile is the store name, used as the option's value.
	Profile string `json:"profile"`

	// Label is what the operator recognises: the certificate's primary name, or
	// the profile slug when it has no names to show.
	Label string `json:"label"`

	// CertPath and KeyPath are the STABLE active paths, which is what the inbound
	// stores. They stay valid across every renewal.
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`

	// Covers is the full name list, so a picker can show what else is on the
	// certificate before it is chosen.
	Covers []string `json:"covers,omitempty"`

	// Expired and SelfSigned let the picker mark an option that will not do what
	// the operator expects, rather than offering it as though it were fine.
	Expired    bool `json:"expired"`
	SelfSigned bool `json:"selfSigned"`
}

// sslCertificateChoices is every managed certificate that actually holds
// something, newest-usable first is not attempted: the order is the profile order,
// which is stable and puts the default first.
//
// Profiles with no certificate are omitted. An empty option would be a path pair
// that does not resolve, and writing that into an inbound is precisely how a
// protocol ends up refusing its whole configuration at startup.
func sslCertificateChoices() []SSLCertificateChoice {
	profiles := ListSSLProfiles()
	out := make([]SSLCertificateChoice, 0, len(profiles))
	for _, p := range profiles {
		if p.Active == nil {
			continue
		}
		label := p.Name
		if ids := p.Active.Identifiers; len(ids) > 0 {
			label = ids[0]
		}
		out = append(out, SSLCertificateChoice{
			Profile:    p.Name,
			Label:      label,
			CertPath:   p.CertPath,
			KeyPath:    p.KeyPath,
			Covers:     p.Active.Identifiers,
			Expired:    p.Active.Expired,
			SelfSigned: p.Active.SelfSigned,
		})
	}
	return out
}

// SSLChoiceForPaths reports which managed certificate a cert/key pair refers to,
// or an empty string when the pair is not one of them.
//
// The picker needs this to show an inbound's CURRENT selection: an inbound stores
// paths, not a profile name, so the only way to render "this one is selected" is to
// match the stored path back to a store. Compared on the cleaned string exactly the
// way samePath and ListSSLConsumers do, so all three agree about what counts as the
// same certificate.
func SSLChoiceForPaths(certPath, keyPath string) string {
	if strings.TrimSpace(certPath) == "" {
		return ""
	}
	for _, c := range sslCertificateChoices() {
		if samePath(certPath, c.CertPath) && (strings.TrimSpace(keyPath) == "" || samePath(keyPath, c.KeyPath)) {
			return c.Profile
		}
	}
	return ""
}
