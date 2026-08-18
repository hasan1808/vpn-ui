package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// The issuance lock
// ---------------------------------------------------------------------------

func TestSSLIssuanceLockRefusesASecondRun(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 4, 14, 35, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	release, err := sslAcquireIssuance(root, SSLOpIssue, []string{"example.com"}, clock)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer release()

	// Refused, not queued: a queued second issuance is a second metered CA request
	// the operator did not knowingly ask for.
	_, err = sslAcquireIssuance(root, SSLOpRenew, []string{"other.example"}, clock)
	if err == nil {
		t.Fatal("a second issuance must be refused while one is running")
	}
	// Local time, because "running since 14:35" is only actionable if it is the
	// clock on the operator's wall.
	want := "issuance already running since " + now.Local().Format("15:04")
	if !strings.Contains(err.Error(), want) {
		t.Errorf("the refusal should say %q, got %q", want, err)
	}
	// And it should explain why serialising matters, not just that it does.
	if !strings.Contains(err.Error(), "port 80") {
		t.Errorf("the refusal should explain the consequence, got %q", err)
	}
}

func TestSSLIssuanceLockBreaksWhenStale(t *testing.T) {
	root := t.TempDir()
	start := time.Date(2026, 8, 4, 14, 0, 0, 0, time.UTC)

	// A run that took the lock and then wedged, which is what acme.sh
	// --standalone does against a firewalled port 80.
	if _, err := sslAcquireIssuance(root, SSLOpIssue, []string{"example.com"}, func() time.Time { return start }); err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// Still inside the window: refused.
	if _, err := sslAcquireIssuance(root, SSLOpIssue, []string{"example.com"},
		func() time.Time { return start.Add(sslLockStaleAfter - time.Minute) }); err == nil {
		t.Fatal("the lock must still hold before the stale timeout")
	}

	// Past it: broken, so a wedged run cannot disable the feature permanently.
	release, err := sslAcquireIssuance(root, SSLOpIssue, []string{"example.com"},
		func() time.Time { return start.Add(sslLockStaleAfter + time.Minute) })
	if err != nil {
		t.Fatalf("a stale lock must be broken, got %v", err)
	}
	release()
}

func TestSSLIssuanceLockBreaksWhenHolderIsGone(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 8, 4, 14, 0, 0, 0, time.UTC)

	// A lock left behind by a process that died, well inside the stale window.
	// The PID check is what stops a crash from costing the operator 20 minutes.
	rec := sslLockRecord{PID: 0x7FFFFFF0, StartedAt: now, Op: SSLOpIssue, Identifiers: []string{"example.com"}}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(root, sslLockFileName), data, 0o600); err != nil {
		t.Fatalf("seed the lock: %v", err)
	}

	release, err := sslAcquireIssuance(root, SSLOpIssue, []string{"example.com"}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("a lock held by a dead process must be broken, got %v", err)
	}
	release()
}

func TestSSLIssuanceLockReleaseAllowsTheNextRun(t *testing.T) {
	root := t.TempDir()
	// The real clock here, because SSLIssuanceRunning is a UI query and reads
	// time.Now(): a pinned past timestamp would look stale to it.
	clock := time.Now

	release, err := sslAcquireIssuance(root, SSLOpIssue, []string{"example.com"}, clock)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, ok := SSLIssuanceRunning(root); !ok {
		t.Error("SSLIssuanceRunning should report the held lock")
	}
	release()
	release() // idempotent

	next, err := sslAcquireIssuance(root, SSLOpRenew, []string{"example.com"}, clock)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	next()
}

func TestSSLProcessAlive(t *testing.T) {
	if !sslProcessAlive(os.Getpid()) {
		t.Error("this process should be reported alive")
	}
	if sslProcessAlive(0) || sslProcessAlive(-1) {
		t.Error("a nonsense pid must not be reported alive")
	}
	if sslProcessAlive(0x7FFFFFF0) {
		t.Error("an out-of-range pid must not be reported alive")
	}
}

// ---------------------------------------------------------------------------
// acme.sh argument construction
// ---------------------------------------------------------------------------

func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func hasArg(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func allValues(args []string, flag string) []string {
	var out []string
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			out = append(out, args[i+1])
		}
	}
	return out
}

// THE ONE THAT MATTERS MOST. acme.sh consults --staging only when ACME_DIRECTORY
// is still empty (acme.sh:3123), and --server sets and exports it during argument
// parsing (acme.sh:9016-9018). So `--server letsencrypt --staging` reaches
// PRODUCTION while the operator believes they are testing, and the tell is a real
// certificate and a spent exact-set slot. Staging is selected by SERVER NAME
// instead, which cannot be silently overridden.
func TestSSLAcmeNeverPassesStagingFlag(t *testing.T) {
	d := newSSLAcmeDriver(t.TempDir())
	for _, staging := range []bool{false, true} {
		for _, challenge := range []string{SSLChallengeCloudflareDNS, SSLChallengeStandaloneDomain, SSLChallengeStandaloneIP, SSLChallengeWebroot} {
			ids := []string{"example.com"}
			if challenge == SSLChallengeStandaloneIP {
				ids = []string{"203.0.113.5"}
			}
			req := SSLIssueRequest{Identifiers: ids, Challenge: challenge, Op: SSLOpIssue, Staging: staging, WebrootPath: "/var/www/html"}
			args, err := d.issueArgs(req)
			if err != nil {
				t.Fatalf("issueArgs: %v", err)
			}
			if hasArg(args, "--staging") || hasArg(args, "--test") {
				t.Fatalf("staging=%v challenge=%s: --staging is silently ignored when --server is passed and must never be used", staging, challenge)
			}
			server, ok := argValue(args, "--server")
			if !ok {
				t.Fatalf("staging=%v challenge=%s: --server must always be explicit (acme.sh's default CA is ZeroSSL)", staging, challenge)
			}
			want := "letsencrypt"
			if staging {
				want = "letsencrypt_test"
			}
			if server != want {
				t.Errorf("staging=%v: --server = %q, want %q", staging, server, want)
			}
		}
	}
}

func TestSSLAcmeNeverForces(t *testing.T) {
	d := newSSLAcmeDriver(t.TempDir())
	// Forcing cannot turn an issuance into a renewal (acme.sh:5155 gates the ARI
	// "replaces" field on the --renew path alone), so it can never save budget and
	// its only effect is to spend a slot the operator was being protected from.
	for _, req := range []SSLIssueRequest{
		{Identifiers: []string{"example.com"}, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpIssue},
		{Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue},
		{Identifiers: []string{"example.com"}, Challenge: SSLChallengeCloudflareDNS, Op: SSLOpIssue},
		{Identifiers: []string{"example.com"}, Challenge: SSLChallengeWebroot, Op: SSLOpIssue, WebrootPath: "/var/www/html"},
	} {
		args, err := d.opArgs(req)
		if err != nil {
			t.Fatalf("opArgs: %v", err)
		}
		if hasArg(args, "--force") || hasArg(args, "-f") {
			t.Errorf("%s: --force must never be used, got %v", req.Challenge, args)
		}
	}
	renew, err := d.renewArgs(SSLIssueRequest{Identifiers: []string{"example.com"}, Op: SSLOpRenew})
	if err != nil {
		t.Fatalf("renewArgs: %v", err)
	}
	if hasArg(renew, "--force") {
		t.Error("--force must never be used on the renew path either")
	}
}

func TestSSLAcmeIssueArgsPerChallenge(t *testing.T) {
	root := t.TempDir()
	d := newSSLAcmeDriver(root)

	t.Run("cloudflare dns-01", func(t *testing.T) {
		args, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"example.com", "*.example.com"},
			Challenge:   SSLChallengeCloudflareDNS, Op: SSLOpIssue,
		})
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := argValue(args, "--dns"); v != "dns_cf" {
			t.Errorf("--dns = %q, want dns_cf", v)
		}
		if hasArg(args, "--standalone") {
			t.Error("DNS-01 must not bind port 80")
		}
		// The FIRST -d is the name acme.sh files the certificate under, and every
		// later --renew and --install-cert addresses it by that name, so the
		// operator's order has to survive.
		ds := allValues(args, "-d")
		if len(ds) != 2 || ds[0] != "example.com" || ds[1] != "*.example.com" {
			t.Errorf("-d list = %v, want [example.com *.example.com] in that order", ds)
		}
	})

	t.Run("standalone domain", func(t *testing.T) {
		args, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"example.com"}, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpIssue,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !hasArg(args, "--standalone") {
			t.Error("HTTP-01 needs --standalone")
		}
		// A 90-day certificate must NOT get the short-lived profile or the
		// short-lived renewal arithmetic.
		if hasArg(args, "--cert-profile") {
			t.Error("a domain certificate must not request the shortlived profile")
		}
		// Explicit listen family: without it acme.sh's standalone server is a bare
		// socat TCP-LISTEN that comes up IPv6-only, and Let's Encrypt's IPv4 fetch
		// gets connection-refused with nothing in the log to explain it.
		if !hasArg(args, "--listen-v4") {
			t.Error("the standalone server needs an explicit address family")
		}
	})

	t.Run("standalone ip", func(t *testing.T) {
		args, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue,
		})
		if err != nil {
			t.Fatal(err)
		}
		// shortlived is the ONLY Let's Encrypt profile whose permitted identifiers
		// include `ip`; without it the order is refused outright.
		if v, _ := argValue(args, "--cert-profile"); v != "shortlived" {
			t.Errorf("--cert-profile = %q, want shortlived", v)
		}
		if !hasArg(args, "--standalone") {
			t.Error("an IP identifier has no DNS-01 option, so --standalone is mandatory")
		}
		// The whole point of fix H1. A positive --days N renews at creation +
		// (N-1) days; only a negative value renews relative to expiry.
		days, ok := argValue(args, "--days")
		if !ok {
			t.Fatal("a short-lived certificate must set --days")
		}
		if !strings.HasPrefix(days, "-") {
			t.Errorf("--days = %q, which is POSITIVE and renews from the creation date. A 160-hour certificate needs a negative value", days)
		}
		if days != sslRenewalDays {
			t.Errorf("--days = %q, want %q", days, sslRenewalDays)
		}
	})

	// WEBROOT. The whole reason it exists is that it binds nothing, so the
	// assertions that matter most are about the flags that must NOT be there.
	t.Run("webroot", func(t *testing.T) {
		args, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"panel.example.com"}, Challenge: SSLChallengeWebroot, Op: SSLOpIssue,
			WebrootPath: "/var/www/html",
		})
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := argValue(args, "--webroot"); !ok || v != "/var/www/html" {
			t.Errorf("--webroot = %q (present=%v), want /var/www/html", v, ok)
		}
		// The point of the feature. --standalone would start a listener that cannot
		// bind, on a host where something else is SUPPOSED to hold port 80, and it
		// would also append a second method to Le_Webroot for every later renewal.
		if hasArg(args, "--standalone") {
			t.Error("webroot must never also pass --standalone: it binds nothing, and that is the entire feature")
		}
		// A listen family is meaningless with no listener, and passing one would
		// suggest in the run log that acme.sh is about to bind something.
		if hasArg(args, "--listen-v4") || hasArg(args, "--listen-v6") {
			t.Errorf("webroot starts no server, so it must not choose an address family: %v", args)
		}
		// A 90-day name certificate must not get the short-lived profile or the
		// short-lived renewal arithmetic.
		if hasArg(args, "--cert-profile") || hasArg(args, "--days") {
			t.Errorf("a webroot certificate for a name must not request the shortlived profile: %v", args)
		}
		if v, _ := argValue(args, "-d"); v != "panel.example.com" {
			t.Errorf("-d = %q", v)
		}
	})

	t.Run("webroot for an IP still needs the shortlived profile", func(t *testing.T) {
		// Nothing about who serves the token changes what Let's Encrypt requires for
		// an IP identifier: shortlived is the only profile that permits one, and the
		// negative --days is what stops acme.sh renewing a 160-hour certificate on
		// 90-day arithmetic. Webroot is the better home for an IP certificate than
		// standalone, precisely because it renews every few days forever.
		args, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"203.0.113.5"}, Challenge: SSLChallengeWebroot, Op: SSLOpIssue,
			WebrootPath: "/var/www/html",
		})
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := argValue(args, "--cert-profile"); v != "shortlived" {
			t.Errorf("--cert-profile = %q, want shortlived", v)
		}
		if v, _ := argValue(args, "--days"); v != sslRenewalDays {
			t.Errorf("--days = %q, want %q", v, sslRenewalDays)
		}
		if hasArg(args, "--standalone") {
			t.Error("an IP over webroot must still not bind port 80")
		}
	})

	t.Run("webroot without a path is an error, not an empty flag", func(t *testing.T) {
		// `--webroot` followed by nothing would make acme.sh swallow the NEXT flag as
		// the directory, which fails in a way that names neither.
		if _, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"example.com"}, Challenge: SSLChallengeWebroot, Op: SSLOpIssue,
		}); err == nil {
			t.Error("a webroot challenge with no path must error")
		}
		if _, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"example.com"}, Challenge: SSLChallengeWebroot, Op: SSLOpIssue, WebrootPath: "   ",
		}); err == nil {
			t.Error("a blank webroot path must error")
		}
	})

	t.Run("listen family follows the request", func(t *testing.T) {
		args, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"2001:db8::1"}, Challenge: SSLChallengeStandaloneIP, Op: SSLOpIssue, ListenV6: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !hasArg(args, "--listen-v6") || hasArg(args, "--listen-v4") {
			t.Errorf("expected --listen-v6 only, got %v", args)
		}
	})

	t.Run("the home is pinned on every invocation", func(t *testing.T) {
		args, err := d.issueArgs(SSLIssueRequest{
			Identifiers: []string{"example.com"}, Challenge: SSLChallengeStandaloneDomain, Op: SSLOpIssue,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Without this the location depends on $HOME, which differs between a
		// systemd start (User=root, no Environment=HOME) and a manual one.
		if v, _ := argValue(args, "--home"); v != SSLAcmeHome(root) {
			t.Errorf("--home = %q, want %q", v, SSLAcmeHome(root))
		}
		if v, _ := argValue(args, "--config-home"); v != SSLAcmeHome(root) {
			t.Errorf("--config-home = %q, want %q", v, SSLAcmeHome(root))
		}
	})

	t.Run("unknown challenge is an error, not a default", func(t *testing.T) {
		if _, err := d.issueArgs(SSLIssueRequest{Identifiers: []string{"example.com"}, Challenge: "tls-alpn", Op: SSLOpIssue}); err == nil {
			t.Error("an unknown challenge must not fall through to a default")
		}
	})
}

func TestSSLAcmeOpArgsRejectsUnknownOp(t *testing.T) {
	d := newSSLAcmeDriver(t.TempDir())
	if _, err := d.opArgs(SSLIssueRequest{Identifiers: []string{"example.com"}, Op: SSLOpReapply}); err == nil {
		t.Error("re-apply must not reach the CA-contacting arg builder")
	}
	if _, err := d.opArgs(SSLIssueRequest{Identifiers: []string{"example.com"}, Op: "nonsense"}); err == nil {
		t.Error("an unknown operation must error")
	}
}

// The failure gate: on the fullchain FILE, never on the domain directory.
// acme.sh creates the directory (and a domain key inside it) even when validation
// fails, so its presence proves nothing. Gating on the directory let a failed
// issuance march into --install-cert (vpn-ui.sh:663-681).
func TestSSLAcmeIssuedChainPathGatesOnTheFile(t *testing.T) {
	root := t.TempDir()
	d := newSSLAcmeDriver(root)
	home := SSLAcmeHome(root)
	domainDir := filepath.Join(home, "example.com")
	if err := os.MkdirAll(domainDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// A failed issuance: the directory exists, and so does a domain key, but there
	// is no chain.
	if err := os.WriteFile(filepath.Join(domainDir, "example.com.key"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := d.issuedChainPath("example.com"); got != "" {
		t.Errorf("a domain directory with no fullchain must not count as issued, got %q", got)
	}

	// An empty fullchain is not a chain either.
	chain := filepath.Join(domainDir, "fullchain.cer")
	if err := os.WriteFile(chain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := d.issuedChainPath("example.com"); got != "" {
		t.Errorf("an empty fullchain must not count as issued, got %q", got)
	}

	if err := os.WriteFile(chain, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := d.issuedChainPath("example.com"); got != chain {
		t.Errorf("issuedChainPath = %q, want %q", got, chain)
	}
}

func TestSSLAcmeIssuedChainPathFindsEccDir(t *testing.T) {
	root := t.TempDir()
	d := newSSLAcmeDriver(root)
	eccDir := filepath.Join(SSLAcmeHome(root), "example.com_ecc")
	if err := os.MkdirAll(eccDir, 0o700); err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(eccDir, "fullchain.cer")
	if err := os.WriteFile(chain, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := d.issuedChainPath("example.com"); got != chain {
		t.Errorf("issuedChainPath = %q, want the _ecc directory %q", got, chain)
	}
}

func TestSSLAcmeHomeRejectsPathWithSpace(t *testing.T) {
	// acme.sh refuses a --home containing a space by name (acme.sh:2986). Caught
	// here so the message points at the path rather than at a shell error.
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := newSSLAcmeDriver(dir)
	err := d.EnsureAcmeHome(func(ProvisionStep) {})
	if err == nil {
		t.Fatal("a store path containing a space must be refused")
	}
	if !strings.Contains(err.Error(), "space") {
		t.Errorf("the error should name the problem, got %v", err)
	}
}

func TestSSLIssueRequestPrimary(t *testing.T) {
	cases := []struct {
		ids  []string
		want string
	}{
		{[]string{"example.com", "www.example.com"}, "example.com"},
		{[]string{"  ", "example.com"}, "example.com"},
		{[]string{"*.example.com", "example.com"}, "*.example.com"},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := (SSLIssueRequest{Identifiers: tc.ids}).Primary(); got != tc.want {
			t.Errorf("Primary(%v) = %q, want %q", tc.ids, got, tc.want)
		}
	}
}

func TestSSLIssueRequestCA(t *testing.T) {
	if got := (SSLIssueRequest{}).CA(); got != sslCAProduction {
		t.Errorf("default CA = %q, want %q", got, sslCAProduction)
	}
	if got := (SSLIssueRequest{Staging: true}).CA(); got != sslCAStaging {
		t.Errorf("staging CA = %q, want %q", got, sslCAStaging)
	}
}

// The install path is stable per identifier set, because acme.sh records it in the
// per-domain conf and reuses it on a later --renew.
func TestSSLAcmeInstallPathsAreStablePerSet(t *testing.T) {
	d := newSSLAcmeDriver(t.TempDir())
	keyA := SSLIdentifierSetKey([]string{"example.com"})
	keyB := SSLIdentifierSetKey([]string{"www.example.com", "example.com"})

	_, certA1, keyA1, err := d.sslInstallPaths(keyA)
	if err != nil {
		t.Fatal(err)
	}
	_, certA2, _, err := d.sslInstallPaths(keyA)
	if err != nil {
		t.Fatal(err)
	}
	if certA1 != certA2 {
		t.Errorf("the landing zone moved between calls: %q then %q", certA1, certA2)
	}
	_, certB, _, err := d.sslInstallPaths(keyB)
	if err != nil {
		t.Fatal(err)
	}
	if certB == certA1 {
		t.Error("two different identifier sets must not share a landing zone")
	}
	if filepath.Dir(certA1) != filepath.Dir(keyA1) {
		t.Error("the certificate and key should land in the same directory")
	}
}
