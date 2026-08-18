package service

import (
	"os"
	"path/filepath"
	"strings"
)

// Addressing a renewal by the name acme.sh actually filed the certificate under.
//
// THE BUG THIS FIXES, because it is subtle and it fails silently.
//
// acme.sh files a certificate in a directory named after the FIRST -d it was
// given, and every later `--renew -d <name>` has to use that same name
// (build/acme/acme.sh:3214). issueArgs preserves the operator's typed order, and
// sslCleanIdentifiers deliberately does not sort, so at issue time the directory
// is named after whatever they typed first.
//
// But the certificate that comes back is parsed with describeChainPEM, which SORTS
// Identifiers (sslstore.go:404). Everything that renews later reads that sorted
// list and takes element 0 as the primary (SSLIssueRequest.Primary). For a set
// typed as "example.com, *.example.com" the directory is example.com while the
// sorted list starts with *.example.com, because '*' is 0x2A and sorts below every
// letter. So the renewal is addressed to a name acme.sh has no conf for.
//
// acme.sh's answer to that is RENEW_SKIP, exit 2 (acme.sh:6115-6117), which is the
// SAME code it returns for "not due yet" — and the run maps exit 2 to success with
// the summary "Not due for renewal". The renewal therefore never happens, the job
// reports success every six hours, and the certificate expires with nothing
// anywhere saying so.
//
// A wildcard hits this every time, because '*' always sorts first, so the natural
// typing order (bare name, then wildcard) is always the broken one. Any multi-name
// certificate can hit it: "panel.example.com, example.com" sorts to
// "example.com" first.
//
// The fix is to stop guessing the primary from the certificate and ask the acme
// home, which is the only thing that knows. Each profile has its own acme home
// holding exactly one certificate, so the answer is unambiguous.

// sslAcmeIssuedPrimary returns the name acme.sh filed this store's certificate
// under, or "" when it cannot tell.
//
// Prefers a directory that matches one of the certificate's own identifiers, so a
// stray directory cannot redirect a renewal at something else. Falls back to the
// only domain directory present when nothing matches, because a store holds one
// certificate and that directory is what --renew must be addressed to.
func sslAcmeIssuedPrimary(storeRoot string, identifiers []string) string {
	home := SSLAcmeHome(storeRoot)
	entries, err := os.ReadDir(home)
	if err != nil {
		return ""
	}

	want := make(map[string]struct{}, len(identifiers))
	for _, id := range identifiers {
		want[strings.ToLower(strings.TrimSpace(id))] = struct{}{}
	}

	var matched, any []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// acme.sh's home also holds its own machinery (ca/, dnsapi/, deploy/).
		// A domain directory is the one carrying <name>.conf, which is exactly
		// what --renew reads.
		domain := strings.TrimSuffix(e.Name(), "_ecc")
		if _, err := os.Stat(filepath.Join(home, e.Name(), domain+".conf")); err != nil {
			continue
		}
		any = append(any, domain)
		if _, ok := want[strings.ToLower(domain)]; ok {
			matched = append(matched, domain)
		}
	}
	if len(matched) == 1 {
		return matched[0]
	}
	if len(matched) > 1 {
		// Two of our own names have state. Ambiguous, and picking one at random
		// could address the renewal at the wrong certificate, so say nothing and
		// let the caller keep what it had.
		return ""
	}
	if len(any) == 1 {
		return any[0]
	}
	return ""
}

// sslRenewIdentifiers reorders a certificate's identifiers so the one acme.sh
// filed it under comes first, which is the name --renew has to use.
//
// Returns the list unchanged when the acme home cannot answer, so a store whose
// state was never carried across behaves exactly as it did before rather than
// losing its renewal entirely.
func sslRenewIdentifiers(storeRoot string, identifiers []string) []string {
	primary := sslAcmeIssuedPrimary(storeRoot, identifiers)
	if primary == "" || len(identifiers) == 0 {
		return identifiers
	}
	if strings.EqualFold(strings.TrimSpace(identifiers[0]), primary) {
		return identifiers
	}
	out := make([]string, 0, len(identifiers))
	out = append(out, primary)
	for _, id := range identifiers {
		if !strings.EqualFold(strings.TrimSpace(id), primary) {
			out = append(out, id)
		}
	}
	return out
}

// sslRenewSkipIsMisaddressed reports that acme.sh skipped because it has no record
// of the name, rather than because the certificate is not due.
//
// Both come back as exit 2, and treating them the same is what let a renewal that
// could never work report success forever. The message is acme.sh's own
// (acme.sh:6116).
func sslRenewSkipIsMisaddressed(out string) bool {
	return strings.Contains(out, "is not an issued domain")
}
