package service

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/hasan1808/pro-ui/logger"
)

// Taking over what the shell flows installed, without asking.
//
// WHY THIS IS AUTOMATIC NOW. deploy.sh and the vpn-ui.sh menu both end their TLS
// path the same way (vpn-ui.sh:709-717): acme.sh issues into ~/.acme.sh/<domain>,
// --install-cert copies the pair to <dbdir>/cert/{fullchain,privkey}.pem, and
// `vpn-ui cert -webCert` points the panel at those two files. That is a perfectly
// good certificate which the panel could see but did not own, so the manager used
// to list it as "not managed here" behind a Take over button, and separately
// warned that acme.sh had its own cron. Two pieces of homework for a state the
// operator did not create and could not have avoided.
//
// So the panel adopts it instead. Adoption is already idempotent and already
// refuses anything it should not touch (ssladopt.go), which is what makes doing it
// unattended reasonable rather than reckless:
//   - a pair whose key does not match its leaf is refused before anything is
//     written,
//   - a path already inside a managed store is refused,
//   - a certificate whose issuer+serial some profile already holds is not offered
//     at all, so running this on every page load re-adopts nothing.
//
// WHAT IT DELIBERATELY DOES NOT DO: it never removes acme.sh's cron unless every
// domain in the legacy acme home has been taken over. That one cron entry renews
// EVERY domain in that home, including ones this panel has nothing to do with, so
// removing it early would strand them silently. See sslLegacyAcmeDomains.

// SSLSyncResult reports what a sync actually did, so a caller can log it rather
// than guess.
type SSLSyncResult struct {
	// Adopted is the profile name each newly taken-over certificate landed in.
	Adopted []string `json:"adopted"`

	// Failed pairs a certificate path with why it could not be taken over. Never
	// fatal: one unreadable pair must not stop the others.
	Failed map[string]string `json:"failed,omitempty"`

	// StoppedLegacyCron reports that acme.sh's own scheduler was removed, which
	// only happens once nothing is left in its home that this panel does not
	// renew itself.
	StoppedLegacyCron bool `json:"stoppedLegacyCron"`

	// LegacyCronKeptFor names the domains still in the legacy acme home that this
	// panel does not manage. Non-empty means the cron was deliberately left alone.
	LegacyCronKeptFor []string `json:"legacyCronKeptFor,omitempty"`
}

// SyncLegacyCertificates takes over every certificate this host is serving that no
// profile owns, and then retires acme.sh's scheduler if it has become redundant.
//
// Safe to call repeatedly: with nothing to do it performs one directory scan and
// returns an empty result.
func (s *SSLService) SyncLegacyCertificates() SSLSyncResult {
	var res SSLSyncResult

	candidates := DetectAdoptableCertificates()
	if len(candidates) == 0 {
		return res
	}

	// RETIRE THE OTHER SCHEDULER FIRST, or do not take anything over at all.
	//
	// Adopting while acme.sh's cron survives creates the exact state this panel is
	// built to avoid: two schedulers renewing the same certificate, the panel's job
	// every six hours and acme.sh four times a day. Both drive --standalone for the
	// HTTP-01 and IP methods, so they race for port 80 and BOTH fail validation,
	// and a failed validation is metered at five per hour per identifier with no
	// override. They also write to two different paths, so whichever the listener
	// is not watching goes quietly stale.
	//
	// The cron can only go when nothing else lives in acme.sh's home, because that
	// one entry renews every domain in it, including any this panel never served
	// (and acme.sh's own --uninstall-cronjob removes the line regardless of which
	// home it was asked about). So when there are strangers in there, the honest
	// move is to leave the whole arrangement alone and say why: a half-migrated box
	// is worse than an unmigrated one.
	if SSLLegacyRenewalInstalled() {
		orphans := sslLegacyDomainsNotManaged()
		if len(orphans) > 0 {
			res.LegacyCronKeptFor = orphans
			logger.Warning("ssl: not taking over the certificate(s) installed outside the panel, because acme.sh's cron also renews",
				strings.Join(orphans, ", "), "- removing it would strand those. Sort them out first.")
			return res
		}
		if err := StopLegacyRenewal(); err != nil {
			logger.Warning("ssl: not taking anything over: acme.sh's own cron could not be removed:", err)
			return res
		}
		res.StoppedLegacyCron = true
		logger.Info("ssl: removed acme.sh's own cron entry; this panel is now the only scheduler")
	}

	for _, c := range candidates {
		name := c.SuggestedName
		if name == "" {
			name = SSLProfileNameFor(sslAdoptableIdentifiers(c))
		}
		out, err := s.AdoptCertificate(name, c.CertPath, c.KeyPath)
		if err != nil {
			if res.Failed == nil {
				res.Failed = map[string]string{}
			}
			res.Failed[c.CertPath] = err.Error()
			logger.Warning("ssl: could not take over", c.CertPath+":", err)
			continue
		}
		res.Adopted = append(res.Adopted, out.Profile)
		logger.Info("ssl: took over the certificate at", c.CertPath, "as", out.Profile)
	}

	return res
}

// sslAdoptableIdentifiers is the names on a candidate, or nothing.
func sslAdoptableIdentifiers(c SSLAdoptable) []string {
	if c.Info == nil {
		return nil
	}
	return c.Info.Identifiers
}

// sslLegacyDomainsNotManaged lists the domains acme.sh's own home still holds that
// no profile in this panel covers.
//
// This is the whole safety check behind retiring that cron. acme.sh installs ONE
// cron entry that runs `--cron`, which walks its home and renews everything in it.
// An operator may well have certificates in there for things this panel never
// served, and removing the entry would stop renewing those with no warning
// anywhere.
func sslLegacyDomainsNotManaged() []string {
	home := sslLegacyAcmeHome()
	entries, err := os.ReadDir(home)
	if err != nil {
		return nil
	}

	// Every name this panel now renews itself, lowercased for comparison.
	managed := map[string]struct{}{}
	for _, name := range SSLProfileNames() {
		root, err := SSLProfileRoot(name)
		if err != nil {
			continue
		}
		store := &SSLStore{root: root}
		if !store.HasActive() {
			continue
		}
		info, err := store.ActiveInfo()
		if err != nil {
			continue
		}
		for _, id := range info.Identifiers {
			managed[strings.ToLower(id)] = struct{}{}
		}
	}

	var orphans []string
	seen := map[string]struct{}{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// acme.sh's home also holds its own machinery (ca/, dnsapi/, http.header
		// and so on). A domain directory is the one with a <name>.conf in it,
		// which is what --cron actually reads.
		domain := strings.TrimSuffix(e.Name(), "_ecc")
		if _, err := os.Stat(filepath.Join(home, e.Name(), domain+".conf")); err != nil {
			continue
		}
		key := strings.ToLower(domain)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if _, ok := managed[key]; !ok {
			orphans = append(orphans, domain)
		}
	}
	return orphans
}
