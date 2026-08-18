package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestLedger returns a ledger in a temp dir whose clock is pinned, so windows
// can be exercised without sleeping.
func newTestLedger(t *testing.T, now time.Time) *SSLLedger {
	t.Helper()
	l, err := OpenSSLLedger(filepath.Join(t.TempDir(), sslLedgerFileName))
	if err != nil {
		t.Fatalf("OpenSSLLedger: %v", err)
	}
	l.now = func() time.Time { return now }
	return l
}

func recordAt(t *testing.T, l *SSLLedger, at time.Time, ids []string, ca, op string, exempt, success bool) {
	t.Helper()
	if err := l.Record(SSLAttempt{At: at, Identifiers: ids, CA: ca, Op: op, Exempt: exempt, Success: success}); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestSSLLedgerExactSetBudget(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com", "www.example.com"}
	setKey := SSLIdentifierSetKey(ids)

	l := newTestLedger(t, now)
	// Five successful non-exempt issuances spread across the trailing week, the
	// oldest six days back.
	oldest := now.Add(-6 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		recordAt(t, l, oldest.Add(time.Duration(i)*20*time.Hour), ids, sslCAProduction, SSLOpIssue, false, true)
	}

	b := l.Budget(setKey, sslCAProduction)
	if !b.Blocked {
		t.Fatalf("a sixth issuance must be refused, got %+v", b)
	}
	if b.Used != 5 || b.Limit != sslExactSetLimit {
		t.Errorf("Used/Limit = %d/%d, want 5/%d", b.Used, b.Limit, sslExactSetLimit)
	}
	// The next slot frees 34h after the OLDEST counted issuance, which is what
	// Let's Encrypt's leaky bucket does.
	want := oldest.Add(sslExactSetRefill)
	if !b.NextFreeAt.Equal(want) {
		t.Errorf("NextFreeAt = %s, want %s (oldest + 34h)", b.NextFreeAt, want)
	}
	if !strings.Contains(b.Reason, "no override") {
		t.Errorf("the refusal should say there is no override form, got %q", b.Reason)
	}
}

func TestSSLLedgerWarnsAtFour(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}
	l := newTestLedger(t, now)
	for i := 0; i < sslExactSetWarnAt; i++ {
		recordAt(t, l, now.Add(-time.Duration(i+1)*time.Hour), ids, sslCAProduction, SSLOpIssue, false, true)
	}
	b := l.Budget(SSLIdentifierSetKey(ids), sslCAProduction)
	if b.Blocked {
		t.Fatal("four issuances must warn, not block")
	}
	if !b.Warn {
		t.Fatalf("four issuances must warn, got %+v", b)
	}
	// The warning has to point at the free path, or the operator does the
	// expensive thing one more time and locks themselves out.
	if !strings.Contains(b.Reason, "Renew") {
		t.Errorf("the warning should steer towards Renew, got %q", b.Reason)
	}
}

func TestSSLLedgerExemptRenewCostsNothing(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}
	setKey := SSLIdentifierSetKey(ids)
	l := newTestLedger(t, now)

	// Twenty ARI-coordinated renewals inside the window. Every one of them is
	// exempt from Let's Encrypt's limits, so counting any of them would refuse an
	// operation that costs nothing.
	for i := 0; i < 20; i++ {
		recordAt(t, l, now.Add(-time.Duration(i)*time.Hour), ids, sslCAProduction, SSLOpRenew, true, true)
	}
	if b := l.Budget(setKey, sslCAProduction); b.Used != 0 || b.Blocked {
		t.Errorf("exempt renewals consumed budget: %+v", b)
	}

	// A failed issuance does not consume the new-certificate bucket either; it
	// consumes the failure bucket, which is a different limit.
	recordAt(t, l, now.Add(-time.Minute), ids, sslCAProduction, SSLOpIssue, false, false)
	if b := l.Budget(setKey, sslCAProduction); b.Used != 0 {
		t.Errorf("a failed issuance consumed new-certificate budget: %+v", b)
	}
}

func TestSSLLedgerBudgetWindowExpires(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}
	l := newTestLedger(t, now)
	// Five issuances, but all older than the 7-day window.
	for i := 0; i < 5; i++ {
		recordAt(t, l, now.Add(-8*24*time.Hour).Add(-time.Duration(i)*time.Hour), ids, sslCAProduction, SSLOpIssue, false, true)
	}
	if b := l.Budget(SSLIdentifierSetKey(ids), sslCAProduction); b.Blocked || b.Used != 0 {
		t.Errorf("issuances outside the 7-day window still count: %+v", b)
	}
}

func TestSSLLedgerFailureBackoffEscalates(t *testing.T) {
	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}

	// One failure per hour, so the 4-per-hour hard stop never fires and the pure
	// backoff is what is under test.
	for _, tc := range []struct {
		failures int
		wantWait time.Duration
	}{
		{1, 1 * time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, 8 * time.Minute},
		{5, 15 * time.Minute},
		{6, 30 * time.Minute},
		{7, 60 * time.Minute},
		{9, 60 * time.Minute}, // capped
	} {
		now := base.Add(time.Duration(tc.failures) * time.Hour)
		l := newTestLedger(t, now)
		var last time.Time
		for i := 0; i < tc.failures; i++ {
			last = base.Add(time.Duration(i) * time.Hour)
			recordAt(t, l, last, ids, sslCAProduction, SSLOpIssue, false, false)
		}
		// Ask at the instant of the last failure so the wait is fully ahead.
		l.now = func() time.Time { return last }
		c := l.Cooldown(ids, sslCAProduction)
		if !c.Blocked {
			t.Errorf("%d consecutive failures: expected a cooldown", tc.failures)
			continue
		}
		if got := c.RetryAt.Sub(last); got != tc.wantWait {
			t.Errorf("%d consecutive failures: wait = %s, want %s", tc.failures, got, tc.wantWait)
		}
	}
}

func TestSSLLedgerFailureHardStopAtFour(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}
	l := newTestLedger(t, now)

	// Four failures inside the trailing hour. Deliberately one below Let's
	// Encrypt's five, so their limit is never actually reached.
	first := now.Add(-50 * time.Minute)
	for i := 0; i < sslFailureHardStop; i++ {
		recordAt(t, l, first.Add(time.Duration(i)*10*time.Minute), ids, sslCAProduction, SSLOpIssue, false, false)
	}
	c := l.Cooldown(ids, sslCAProduction)
	if !c.Blocked {
		t.Fatalf("4 failures in an hour must hard stop, got %+v", c)
	}
	if c.FailuresInWindow != sslFailureHardStop {
		t.Errorf("FailuresInWindow = %d, want %d", c.FailuresInWindow, sslFailureHardStop)
	}
	// The block lifts when the oldest of the four ages out of the hour.
	if want := first.Add(sslFailureWindow); !c.RetryAt.Equal(want) {
		t.Errorf("RetryAt = %s, want %s (oldest + 1h)", c.RetryAt, want)
	}
	if !strings.Contains(c.Reason, "5 per hour") {
		t.Errorf("the message should explain the real limit, got %q", c.Reason)
	}
}

func TestSSLLedgerSuccessResetsBackoff(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}
	l := newTestLedger(t, now)

	// Three failures, deliberately one below the hard stop, so what is under test
	// is purely the consecutive-failure backoff.
	for i := 0; i < 3; i++ {
		recordAt(t, l, now.Add(-time.Duration(3-i)*time.Minute), ids, sslCAProduction, SSLOpIssue, false, false)
	}
	if c := l.Cooldown(ids, sslCAProduction); !c.Blocked {
		t.Fatalf("three recent failures should back off, got %+v", c)
	}

	// A success proves whatever was misconfigured is fixed, so the backoff goes.
	recordAt(t, l, now.Add(-time.Second), ids, sslCAProduction, SSLOpIssue, false, true)
	c := l.Cooldown(ids, sslCAProduction)
	if c.Blocked {
		t.Errorf("a success must clear the backoff, got %+v", c)
	}
	if c.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after a success, want 0", c.ConsecutiveFailures)
	}
}

// The hard stop mirrors Let's Encrypt's own failure bucket, and theirs refills
// with time, not with a success. Four failures then a success still leaves them
// holding a single slot, so we must not hand out a clean sheet.
func TestSSLLedgerHardStopSurvivesASuccess(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}
	l := newTestLedger(t, now)

	first := now.Add(-30 * time.Minute)
	for i := 0; i < sslFailureHardStop; i++ {
		recordAt(t, l, first.Add(time.Duration(i)*time.Minute), ids, sslCAProduction, SSLOpIssue, false, false)
	}
	recordAt(t, l, now.Add(-time.Second), ids, sslCAProduction, SSLOpIssue, false, true)

	c := l.Cooldown(ids, sslCAProduction)
	if !c.Blocked {
		t.Fatalf("the hard stop must outlive a success, got %+v", c)
	}
	if c.ConsecutiveFailures != 0 {
		t.Errorf("the consecutive counter should still have been reset, got %d", c.ConsecutiveFailures)
	}
	if want := first.Add(sslFailureWindow); !c.RetryAt.Equal(want) {
		t.Errorf("RetryAt = %s, want %s (the oldest failure ageing out)", c.RetryAt, want)
	}
}

// Staging has its own account namespace and a 200/hour failure budget, so
// debugging against it must not lock the operator out of production.
func TestSSLLedgerStagingFailuresDoNotBlockProduction(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	ids := []string{"example.com"}
	l := newTestLedger(t, now)
	for i := 0; i < 10; i++ {
		recordAt(t, l, now.Add(-time.Duration(i)*time.Minute), ids, sslCAStaging, SSLOpIssue, false, false)
	}
	if c := l.Cooldown(ids, sslCAProduction); c.Blocked {
		t.Errorf("staging failures blocked production: %+v", c)
	}
	if c := l.Cooldown(ids, sslCAStaging); !c.Blocked {
		t.Error("staging failures should still gate further staging attempts")
	}
}

// The cooldown is per identifier, and the whole set is gated by its worst member.
func TestSSLLedgerCooldownIsPerIdentifier(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	l := newTestLedger(t, now)
	for i := 0; i < sslFailureHardStop; i++ {
		recordAt(t, l, now.Add(-time.Duration(i+1)*time.Minute), []string{"bad.example"}, sslCAProduction, SSLOpIssue, false, false)
	}
	if c := l.Cooldown([]string{"good.example"}, sslCAProduction); c.Blocked {
		t.Errorf("an unrelated identifier was blocked: %+v", c)
	}
	c := l.Cooldown([]string{"good.example", "bad.example"}, sslCAProduction)
	if !c.Blocked {
		t.Fatal("a set containing a blocked identifier must be blocked")
	}
	if c.Identifier != "bad.example" {
		t.Errorf("the block should name bad.example, got %q", c.Identifier)
	}
}

func TestSSLLedgerMinAgeRefusesEarlyRenewal(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		lifetime time.Duration
		age      time.Duration
		wantErr  bool
	}{
		// A 160-hour IP certificate: the floor is a quarter of that, 40h.
		{"160h cert at 1h", 160 * time.Hour, time.Hour, true},
		{"160h cert at 39h", 160 * time.Hour, 39 * time.Hour, true},
		{"160h cert at 41h", 160 * time.Hour, 41 * time.Hour, false},
		{"90 day cert at 1 day", 90 * 24 * time.Hour, 24 * time.Hour, true},
		{"90 day cert at 60 days", 90 * 24 * time.Hour, 60 * 24 * time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := &SSLCertInfo{
				NotBefore: now.Add(-tc.age),
				NotAfter:  now.Add(tc.lifetime - tc.age),
				Lifetime:  tc.lifetime,
			}
			info.RenewalDueAt = info.NotAfter.Add(-tc.lifetime / 3)
			err := sslCheckMinAge(info, now)
			if tc.wantErr && err == nil {
				t.Fatal("expected the early renewal to be refused")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "spend a new-certificate slot") {
				t.Errorf("the refusal should explain the cost, got %q", err)
			}
		})
	}
}

func TestSSLIdentifierSetKeyNormalisation(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		same bool
	}{
		{"order does not matter", []string{"a.example", "b.example"}, []string{"b.example", "a.example"}, true},
		{"case does not matter", []string{"Example.COM"}, []string{"example.com"}, true},
		{"whitespace does not matter", []string{"  example.com  "}, []string{"example.com"}, true},
		{"trailing root dot does not matter", []string{"example.com."}, []string{"example.com"}, true},
		{"duplicates collapse", []string{"a.example", "a.example"}, []string{"a.example"}, true},
		{"IPv6 spelling does not matter", []string{"2001:DB8:0:0::1"}, []string{"2001:db8::1"}, true},
		{"a superset is a different bucket", []string{"example.com"}, []string{"example.com", "www.example.com"}, false},
		{"a wildcard is a different name", []string{"example.com"}, []string{"*.example.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ka, kb := SSLIdentifierSetKey(tc.a), SSLIdentifierSetKey(tc.b)
			if (ka == kb) != tc.same {
				t.Errorf("key(%v)=%q key(%v)=%q, same=%v want %v", tc.a, ka, tc.b, kb, ka == kb, tc.same)
			}
		})
	}
}

// The budget has to key off the normalised set, or listing the same names in a
// different order hands the operator a fresh budget that does not exist.
func TestSSLLedgerBudgetIgnoresIdentifierOrder(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	l := newTestLedger(t, now)
	for i := 0; i < 5; i++ {
		recordAt(t, l, now.Add(-time.Duration(i+1)*time.Hour),
			[]string{"www.example.com", "example.com"}, sslCAProduction, SSLOpIssue, false, true)
	}
	// Same set, opposite order, mixed case.
	b := l.Budget(SSLIdentifierSetKey([]string{"Example.com", "WWW.example.com"}), sslCAProduction)
	if !b.Blocked {
		t.Fatalf("the same set in a different order got a fresh budget: %+v", b)
	}
}

func TestSSLLedgerPersistsAndReloads(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, sslLedgerFileName)

	l, err := OpenSSLLedger(path)
	if err != nil {
		t.Fatalf("OpenSSLLedger: %v", err)
	}
	l.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		recordAt(t, l, now.Add(-time.Duration(i+1)*time.Hour), []string{"example.com"}, sslCAProduction, SSLOpIssue, false, true)
	}

	// A restart must not hand back a fresh budget: Let's Encrypt's counter does
	// not restart with us.
	reopened, err := OpenSSLLedger(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	reopened.now = func() time.Time { return now }
	if b := reopened.Budget(SSLIdentifierSetKey([]string{"example.com"}), sslCAProduction); !b.Blocked {
		t.Fatalf("the budget was lost across a reload: %+v", b)
	}
}

// A corrupt ledger is a hard error rather than a silent reset, because the
// permissive answer is the one that spends a slot the operator does not have.
func TestSSLLedgerCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), sslLedgerFileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := OpenSSLLedger(path)
	if err == nil {
		t.Fatal("a corrupt ledger must not be silently treated as empty")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("the error should say the file is corrupt, got %v", err)
	}
}

func TestSSLLedgerMissingFileIsEmpty(t *testing.T) {
	l, err := OpenSSLLedger(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("a missing ledger should be an empty one, got %v", err)
	}
	if len(l.Attempts()) != 0 {
		t.Error("a missing ledger should have no attempts")
	}
}
