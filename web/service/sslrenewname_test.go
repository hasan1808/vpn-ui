package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// acmeHomeWith builds a store whose acme home holds per-domain state for the given
// names, the way acme.sh lays it out: a directory per domain carrying <name>.conf.
func acmeHomeWith(t *testing.T, domains ...string) string {
	t.Helper()
	root := t.TempDir()
	home := SSLAcmeHome(root)
	// The machinery acme.sh keeps beside the domains, which must never be mistaken
	// for one.
	for _, junk := range []string{"ca", "dnsapi", "deploy"} {
		if err := os.MkdirAll(filepath.Join(home, junk), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range domains {
		dir := filepath.Join(home, d)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, d+".conf"), []byte("Le_Domain='"+d+"'\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// THE BUG. A certificate's identifiers are sorted when it is parsed, and '*' sorts
// below every letter, so a wildcard always lands at index 0. acme.sh filed the
// certificate under whatever was typed FIRST, so a renewal addressed by the sorted
// list goes to a name acme.sh has no conf for.
func TestRenewIdentifiersUsesTheNameAcmeFiledItUnder(t *testing.T) {
	// Typed "example.com, *.example.com", so acme.sh's directory is example.com.
	root := acmeHomeWith(t, "example.com")
	// ...but the parsed certificate reports them sorted, wildcard first.
	sorted := []string{"*.example.com", "example.com"}

	got := sslRenewIdentifiers(root, sorted)
	if len(got) == 0 || got[0] != "example.com" {
		t.Fatalf("renew would be addressed to %q; acme.sh filed the certificate under example.com, so it would answer 'not an issued domain' forever", got)
	}
	// Nothing may be dropped: the set still has to describe the same certificate.
	if len(got) != len(sorted) {
		t.Errorf("identifiers = %v, want the same two names reordered", got)
	}
}

// The other order has to keep working untouched.
func TestRenewIdentifiersLeavesACorrectOrderAlone(t *testing.T) {
	root := acmeHomeWith(t, "*.example.com")
	in := []string{"*.example.com", "example.com"}
	got := sslRenewIdentifiers(root, in)
	if got[0] != "*.example.com" {
		t.Errorf("identifiers = %v, want the wildcard kept first", got)
	}
}

// A plain multi-name certificate hits the same bug: "panel.example.com,
// example.com" sorts example.com to the front.
func TestRenewIdentifiersFixesPlainMultiNameSets(t *testing.T) {
	root := acmeHomeWith(t, "panel.example.com")
	got := sslRenewIdentifiers(root, []string{"example.com", "panel.example.com"})
	if got[0] != "panel.example.com" {
		t.Errorf("identifiers = %v, want panel.example.com first", got)
	}
}

// An _ecc suffix is acme.sh's own, not part of the domain.
func TestRenewIdentifiersHandlesTheEccSuffix(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(SSLAcmeHome(root), "example.com_ecc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example.com.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := sslRenewIdentifiers(root, []string{"*.example.com", "example.com"})
	if got[0] != "example.com" {
		t.Errorf("identifiers = %v, want example.com resolved from the _ecc directory", got)
	}
}

// With no acme state at all, the list has to come back untouched: a store whose
// renewal state was never carried across must behave exactly as before rather than
// have its identifiers rewritten on a guess.
func TestRenewIdentifiersIsANoOpWithoutAcmeState(t *testing.T) {
	in := []string{"*.example.com", "example.com"}
	got := sslRenewIdentifiers(t.TempDir(), in)
	if len(got) != 2 || got[0] != in[0] {
		t.Errorf("identifiers = %v, want them unchanged", got)
	}
}

// Two of our own names carrying state is ambiguous. Picking one could address the
// renewal at the wrong certificate, so nothing is changed.
func TestRenewIdentifiersRefusesToGuessWhenAmbiguous(t *testing.T) {
	root := acmeHomeWith(t, "example.com", "panel.example.com")
	in := []string{"example.com", "panel.example.com"}
	got := sslRenewIdentifiers(root, in)
	if got[0] != in[0] {
		t.Errorf("identifiers = %v, want them left alone when two directories match", got)
	}
}

// A directory for something else entirely must not capture the renewal, but when
// it is the ONLY state present it is still what --renew has to be addressed to,
// because a store holds exactly one certificate.
func TestRenewIdentifiersPrefersAMatchingName(t *testing.T) {
	root := acmeHomeWith(t, "stranger.example.net", "example.com")
	got := sslRenewIdentifiers(root, []string{"*.example.com", "example.com"})
	if got[0] != "example.com" {
		t.Errorf("identifiers = %v, want our own name preferred over the stranger", got)
	}
}

// The two meanings of exit code 2 have to be told apart, because treating a
// misaddressed renewal as "not due" is what hid the bug above: the job reported
// success every six hours while the certificate expired.
func TestRenewSkipTellsMisaddressedFromNotDue(t *testing.T) {
	misaddressed := "[Mon Aug 10] Renewing: '*.example.com'\n[Mon Aug 10] '*.example.com' is not an issued domain, skipping."
	notDue := "[Mon Aug 10] Renewing: 'example.com'\n[Mon Aug 10] Skipping. Next renewal time is: 2026-10-01T00:00:00Z"

	if !sslRenewSkipIsMisaddressed(misaddressed) {
		t.Error("a renewal addressed to a name acme.sh never issued was read as 'not due yet'")
	}
	if sslRenewSkipIsMisaddressed(notDue) {
		t.Error("an ordinary not-due skip was reported as a failure, which would poison the backoff")
	}
}

// RenewAllDue used to start each profile's run and move straight on. Start
// returns as soon as the background goroutine launches and only one run is
// allowed at a time, so every profile after the first was refused milliseconds
// later and simply not renewed: one certificate per six-hourly tick, whatever
// how many were due. This pins the wait that fixes it.
func TestWaitForRunReturnsWhenTheRunEnds(t *testing.T) {
	var s SSLService

	sslRun.mu.Lock()
	sslRun.running = true
	sslRun.mu.Unlock()
	t.Cleanup(func() {
		sslRun.mu.Lock()
		sslRun.running = false
		sslRun.mu.Unlock()
	})

	// Nothing is waiting on this but the test; it stands in for the background
	// run finishing.
	go func() {
		time.Sleep(sslRenewWaitStep)
		sslRun.mu.Lock()
		sslRun.running = false
		sslRun.mu.Unlock()
	}()

	start := time.Now()
	if !s.sslWaitForRun() {
		t.Fatal("sslWaitForRun reported a timeout for a run that finished")
	}
	if waited := time.Since(start); waited > sslRenewWaitMax {
		t.Errorf("waited %v, which is past the ceiling", waited)
	}
}

// An idle panel must not make the loop wait at all, or a tick with nothing due
// would still crawl.
func TestWaitForRunReturnsImmediatelyWhenIdle(t *testing.T) {
	var s SSLService
	sslRun.mu.Lock()
	sslRun.running = false
	sslRun.mu.Unlock()

	start := time.Now()
	if !s.sslWaitForRun() {
		t.Fatal("an idle panel reported a timeout")
	}
	if waited := time.Since(start); waited > sslRenewWaitStep {
		t.Errorf("an idle panel took %v; it should return without sleeping", waited)
	}
}
