package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/backend"
)

// The issuance ledger: every attempt that contacted a CA, and the local limits
// enforced BEFORE dialling out.
//
// WHY LOCAL LIMITS AT ALL. Let's Encrypt's own limits are the reason this whole
// feature is shaped the way it is, and hitting one is not a retry-in-a-moment
// error, it is a lockout measured in hours or days:
//
//   - Authorization failures, 5 per identifier per account per hour, one slot back
//     every 12 minutes, NO override form. This is the one an operator hits while
//     DEBUGGING, because every failed validation costs a slot.
//   - New certificates for an EXACT set of identifiers, 5 per 7 days, one slot back
//     every ~34 hours, NO override form. This is the one an operator hits when
//     validation SUCCEEDS and they keep re-issuing "to be sure". A days-long
//     lockout, and the expensive one.
//   - Certificates per registered domain, 50 per 7 days. Overridable by form, so it
//     is reported but not enforced here.
//
// We refuse BEFORE the request so a mistake costs nothing, and we deliberately
// stop one short of the failure limit so this panel can never be the thing that
// exhausts it.
//
// WHERE THIS LIVES, AND WHY IT IS NOT A DATABASE TABLE.
//
// A file inside the certificate store, next to the pinned ACME home. The ledger
// describes what THIS host has already asked of THIS ACME account, and the account
// key it is paired with is itself a file in that home, not a row in the database.
// Giving the two the same lifetime is the whole argument:
//
//   - A database import (see migration.go) REPLACES the database wholesale and
//     preserves only the individual setting keys listed at migration.go:36-45. A
//     ledger table would come across from the backup, i.e. from a DIFFERENT host
//     with a different ACME account and different identifiers, or would be empty
//     for a stock 3x-ui backup. A file in the store is untouched by an import,
//     because an import only swaps the .db file.
//   - Losing the ledger does NOT reset Let's Encrypt's counters. It only makes US
//     more permissive than they are, which is the dangerous direction: we would
//     cheerfully spend budget that is already spent. So the design question is not
//     "is it backed up" but "can it be replaced by someone else's copy", and a
//     table can, while a file in the store cannot.
//   - An uninstall removes the cert directory (uninstall.go:384-386), taking the
//     ledger and the ACME home together, which is right: an uninstall is an
//     explicit request to leave nothing behind.
//
// The one gap this leaves, stated plainly because it cannot be closed from here: a
// REINSTALL on the same host reusing the same address starts with an empty ledger,
// while Let's Encrypt's exact-set counter is not account-scoped and keeps counting.
// For the first few issuances after a reinstall our answer is more optimistic than
// theirs, and only theirs is binding.

const (
	// sslCAProduction / sslCAStaging name the two CA namespaces. Staging has its
	// own account namespace and a 200/hour failure budget, so its attempts are
	// ledgered separately and never consume a production slot.
	sslCAProduction = "production"
	sslCAStaging    = "staging"

	// The exact-set bucket, mirrored from Let's Encrypt so our answer matches
	// theirs. Their bucket refills one token every 168h/5 = 33.6h; 34h is that
	// rounded UP, which can only ever make us report a slot as free later than it
	// really is. Rounding the other way would hand the operator a time at which
	// the request still fails.
	sslExactSetLimit  = 5
	sslExactSetWarnAt = 4
	sslExactSetWindow = 7 * 24 * time.Hour
	sslExactSetRefill = 34 * time.Hour

	// The failure gate. Four, deliberately one below Let's Encrypt's five, so the
	// operator hits OUR stop (free, instantly reversible, and it explains itself)
	// and never theirs.
	sslFailureHardStop = 4
	sslFailureWindow   = time.Hour

	// sslLedgerRetention bounds the file. Longer than the longest window queried
	// (7 days) so the UI can show recent history, short enough that the file stays
	// a few kilobytes on a host that renews every few days.
	sslLedgerRetention = 30 * 24 * time.Hour

	sslLedgerFileName = "ledger.json"
)

// sslFailureBackoff is the wait after N consecutive failures for one identifier.
// It exists on top of the hard stop because the hard stop only catches four
// failures inside an hour: a slow retry loop (one an hour, forever) would never
// trip it while still burning a Let's Encrypt slot every time. The last entry is
// the cap, held for any further failures.
var sslFailureBackoff = []time.Duration{
	1 * time.Minute,
	2 * time.Minute,
	4 * time.Minute,
	8 * time.Minute,
	15 * time.Minute,
	30 * time.Minute,
	60 * time.Minute,
}

// SSLAttempt is one recorded conversation with a CA.
type SSLAttempt struct {
	At          time.Time `json:"at"`
	Identifiers []string  `json:"identifiers"` // normalised and sorted
	SetKey      string    `json:"setKey"`
	CA          string    `json:"ca"` // sslCAProduction or sslCAStaging
	Op          string    `json:"op"` // SSLOpIssue / SSLOpRenew / SSLOpReapply
	Exempt      bool      `json:"exempt"`
	Success     bool      `json:"success"`
	Message     string    `json:"message,omitempty"`
}

// SSLLedger is the append-only record plus the checks derived from it.
type SSLLedger struct {
	path string

	mu       sync.Mutex
	attempts []SSLAttempt

	// now is a test seam, written once at construction. Every window in this file
	// is measured against it so tests can place attempts in the past without
	// sleeping.
	now func() time.Time
}

// SSLLedgerPath is where the ledger lives for a given store root.
func SSLLedgerPath(storeRoot string) string {
	return filepath.Join(storeRoot, sslLedgerFileName)
}

// OpenSSLLedger loads the ledger, treating a missing file as an empty one.
//
// A CORRUPT file is a deliberate hard error rather than a silent reset. An
// unreadable ledger means we cannot tell how much budget is left, and the
// permissive answer ("none used") is the one that can spend a slot the operator
// does not have. Refusing makes the operator look, which costs a minute; guessing
// can cost days.
func OpenSSLLedger(path string) (*SSLLedger, error) {
	l := &SSLLedger{path: path, now: time.Now}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ssl ledger: read %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return l, nil
	}
	if err := json.Unmarshal(data, &l.attempts); err != nil {
		return nil, fmt.Errorf("ssl ledger: %s is corrupt (%w). It records how much Let's Encrypt budget has been spent, so it is not reset automatically. Move it aside only if you accept that the next few issuances are unguarded", path, err)
	}
	return l, nil
}

// Record appends an attempt and persists immediately. Every CA-contacting
// operation calls this, success or failure, because a failure is exactly the thing
// the cooldown is computed from.
func (l *SSLLedger) Record(a SSLAttempt) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if a.At.IsZero() {
		a.At = l.now()
	}
	a.Identifiers = NormalizeSSLIdentifiers(a.Identifiers)
	if a.SetKey == "" {
		a.SetKey = SSLIdentifierSetKey(a.Identifiers)
	}
	if a.CA == "" {
		a.CA = sslCAProduction
	}
	l.attempts = append(l.attempts, a)
	return l.saveLocked()
}

func (l *SSLLedger) saveLocked() error {
	cutoff := l.now().Add(-sslLedgerRetention)
	kept := l.attempts[:0]
	for _, a := range l.attempts {
		if a.At.After(cutoff) {
			kept = append(kept, a)
		}
	}
	l.attempts = kept

	data, err := json.MarshalIndent(l.attempts, "", "  ")
	if err != nil {
		return fmt.Errorf("ssl ledger: encode: %w", err)
	}
	// 0600: the identifier list is not secret, but the file sits beside private
	// keys and inherits the store's posture rather than the process umask.
	if err := backend.WriteFileAtomic(l.path, data, 0o600); err != nil {
		return fmt.Errorf("ssl ledger: write %s: %w", l.path, err)
	}
	return nil
}

// Attempts returns a copy of the record, newest first.
func (l *SSLLedger) Attempts() []SSLAttempt {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]SSLAttempt, len(l.attempts))
	copy(out, l.attempts)
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

// SSLBudget is the exact-set new-certificate budget for one identifier set.
type SSLBudget struct {
	SetKey  string `json:"setKey"`
	Used    int    `json:"used"`
	Limit   int    `json:"limit"`
	Warn    bool   `json:"warn"`
	Blocked bool   `json:"blocked"`

	// NextFreeAt is when the next slot frees, and is meaningful only when Used is
	// above zero. It has no omitempty because encoding/json never omits a struct:
	// a zero time serialises as "0001-01-01T00:00:00Z", so a consumer must check
	// Used rather than test the string.
	NextFreeAt time.Time `json:"nextFreeAt"`
	Reason     string    `json:"reason,omitempty"`
}

// Budget reports the exact-set new-certificate budget.
//
// Only NON-EXEMPT successes count. A renewal that went out on the --renew path
// carried an RFC 9773 "replaces" field and is exempt from every Let's Encrypt rate
// limit, so counting it would make us refuse issuances that cost nothing. A FAILED
// issuance does not consume this bucket either (it consumes the failure bucket,
// which Cooldown owns).
//
// The trailing-window count and Let's Encrypt's leaky bucket agree on the decision
// that matters: with a capacity of 5 and one token back every 33.6 hours, five
// successes inside 7 days is exactly a drained bucket.
func (l *SSLLedger) Budget(setKey, ca string) SSLBudget {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-sslExactSetWindow)
	var counted []time.Time
	for _, a := range l.attempts {
		if a.SetKey != setKey || a.CA != ca || a.Exempt || !a.Success {
			continue
		}
		if a.At.After(cutoff) {
			counted = append(counted, a.At)
		}
	}
	sort.Slice(counted, func(i, j int) bool { return counted[i].Before(counted[j]) })

	b := SSLBudget{SetKey: setKey, Used: len(counted), Limit: sslExactSetLimit}
	if len(counted) > 0 {
		b.NextFreeAt = counted[0].Add(sslExactSetRefill)
	}
	switch {
	case b.Used >= sslExactSetLimit:
		b.Blocked = true
		b.Warn = true
		b.Reason = fmt.Sprintf(
			"Let's Encrypt allows %d new certificates per 7 days for this exact set of names and %d have already been issued. There is no override form for this limit. The next slot frees at %s.",
			sslExactSetLimit, b.Used, sslFormatTime(b.NextFreeAt))
	case b.Used >= sslExactSetWarnAt:
		b.Warn = true
		b.Reason = fmt.Sprintf(
			"%d of %d new certificates for this exact set of names have been issued in the last 7 days. One more and this set is locked out until %s. Use Renew (which is exempt from this limit) rather than Issue.",
			b.Used, sslExactSetLimit, sslFormatTime(b.NextFreeAt))
	}
	return b
}

// SSLCooldown is the per-identifier failure gate.
type SSLCooldown struct {
	Identifier          string `json:"identifier"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	FailuresInWindow    int    `json:"failuresInWindow"`
	Blocked             bool   `json:"blocked"`

	// RetryAt is meaningful only when Blocked is true; see the note on
	// SSLBudget.NextFreeAt about zero times and omitempty.
	RetryAt time.Time `json:"retryAt"`
	Reason  string    `json:"reason,omitempty"`
}

// Cooldown reports the most restrictive per-identifier failure gate across a set.
//
// Keyed by (identifier, CA) rather than by identifier alone, because Let's
// Encrypt's failure bucket is per account and staging is a separate account
// namespace with its own 200/hour budget. A burst of staging failures, which is
// exactly what an operator debugging the plumbing produces, must not lock them out
// of production.
func (l *SSLLedger) Cooldown(identifiers []string, ca string) SSLCooldown {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	worst := SSLCooldown{}
	for _, id := range NormalizeSSLIdentifiers(identifiers) {
		c := l.cooldownForLocked(id, ca, now)
		// The gate that pushes the retry furthest out is the one that governs,
		// and a blocked identifier always beats an unblocked one.
		if c.Blocked && (!worst.Blocked || c.RetryAt.After(worst.RetryAt)) {
			worst = c
		} else if !worst.Blocked && c.ConsecutiveFailures > worst.ConsecutiveFailures {
			worst = c
		}
	}
	return worst
}

func (l *SSLLedger) cooldownForLocked(identifier, ca string, now time.Time) SSLCooldown {
	c := SSLCooldown{Identifier: identifier}

	// Consecutive failures, walking backwards to the most recent SUCCESS. A
	// success resets the count, because it proves whatever was broken is fixed.
	var relevant []SSLAttempt
	for _, a := range l.attempts {
		if a.CA != ca || !sslContains(a.Identifiers, identifier) {
			continue
		}
		relevant = append(relevant, a)
	}
	sort.Slice(relevant, func(i, j int) bool { return relevant[i].At.Before(relevant[j].At) })

	var lastFailure time.Time
	windowStart := now.Add(-sslFailureWindow)
	var inWindow []time.Time
	for _, a := range relevant {
		if a.Success {
			c.ConsecutiveFailures = 0
			lastFailure = time.Time{}
			continue
		}
		c.ConsecutiveFailures++
		lastFailure = a.At
		if a.At.After(windowStart) {
			inWindow = append(inWindow, a.At)
		}
	}
	c.FailuresInWindow = len(inWindow)

	// The hard stop first: it is the one that keeps us clear of Let's Encrypt's
	// own limit, so it wins over the backoff when both apply.
	//
	// Note what it deliberately does NOT do: reset on a success. The backoff above
	// resets, because a success proves whatever was misconfigured is fixed. This
	// does not, because it mirrors Let's Encrypt's authorization-failure bucket,
	// and THEIR bucket only refills with time. Four failures then a success still
	// leaves them holding one slot, so a fifth request inside the hour really can
	// hit their limit. Clearing this on a success would make us more permissive
	// than the CA at exactly the moment the operator is most likely to keep
	// clicking.
	if len(inWindow) >= sslFailureHardStop {
		sort.Slice(inWindow, func(i, j int) bool { return inWindow[i].Before(inWindow[j]) })
		c.Blocked = true
		c.RetryAt = inWindow[0].Add(sslFailureWindow)
		c.Reason = fmt.Sprintf(
			"%d validation failures for %s in the last hour. Let's Encrypt allows 5 per hour and refusing at %d keeps a slot in reserve, so the cause can be fixed and verified without a lockout. Retry after %s, and fix the cause first: another failure buys nothing.",
			len(inWindow), identifier, sslFailureHardStop, sslFormatTime(c.RetryAt))
		return c
	}

	if c.ConsecutiveFailures > 0 && !lastFailure.IsZero() {
		wait := sslFailureBackoff[min(c.ConsecutiveFailures-1, len(sslFailureBackoff)-1)]
		retryAt := lastFailure.Add(wait)
		if now.Before(retryAt) {
			c.Blocked = true
			c.RetryAt = retryAt
			c.Reason = fmt.Sprintf(
				"The last %s for %s failed. Waiting %s before the next attempt so a repeated mistake does not spend the 5-per-hour validation budget. Retry after %s.",
				sslPluralAttempts(c.ConsecutiveFailures), identifier,
				sslFormatDuration(wait), sslFormatTime(retryAt))
		}
	}
	return c
}

// MinAgeCheck refuses a renewal of a certificate that is too young, regardless of
// what acme.sh thinks. See sslMinRenewalAge for the reasoning; this is the check
// that makes a bad --days value or an over-firing cron a local no-op instead of a
// week-long lockout.
func sslCheckMinAge(info *SSLCertInfo, now time.Time) error {
	if info == nil {
		return nil
	}
	minAge := sslMinRenewalAge(info.Lifetime)
	age := now.Sub(info.NotBefore)
	if age >= minAge {
		return nil
	}
	return fmt.Errorf(
		"the current certificate is only %s old and this panel will not renew one younger than %s (a quarter of its %s lifetime). It was issued at %s and renewal is due at %s. Nothing is wrong; renewing now would spend a new-certificate slot for no gain",
		sslFormatDuration(age), sslFormatDuration(minAge), sslFormatDuration(info.Lifetime),
		sslFormatTime(info.NotBefore), sslFormatTime(info.RenewalDueAt))
}

// NormalizeSSLIdentifiers puts an identifier list into the one canonical form
// everything else keys on: trimmed, lowercased, IP literals canonicalised, sorted,
// deduplicated.
//
// Sorting is what makes the ledger key stable. Let's Encrypt counts the EXACT set,
// so [a.com b.com] and [b.com a.com] are one bucket to them and must be one entry
// here, or a caller that happens to list the names the other way round gets a
// fresh budget that does not exist.
//
// IP literals are canonicalised (2001:DB8::0:1 and 2001:db8::1 are one address) so
// two spellings of one address cannot look like two identifiers. Note this is only
// for the KEY: the string handed to acme.sh stays exactly what the operator typed,
// because a normalisation there would request a certificate for an address they
// did not name.
func NormalizeSSLIdentifiers(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.ToLower(strings.TrimSpace(raw))
		id = strings.TrimSuffix(id, ".") // a trailing root dot is the same name
		if id == "" {
			continue
		}
		if ip := net.ParseIP(id); ip != nil {
			id = ip.String()
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// SSLIdentifierSetKey is the ledger key for an identifier set.
func SSLIdentifierSetKey(ids []string) string {
	return strings.Join(NormalizeSSLIdentifiers(ids), ",")
}

func sslContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// sslFormatTime is the one place wall-clock times are rendered for the operator.
// Local time with the zone shown, because "retry after 14:05" is only actionable
// if it is the clock on their wall, and the zone stops a UTC host from reading as
// their own.
func sslFormatTime(t time.Time) string {
	if t.IsZero() {
		return "an unknown time"
	}
	return t.Local().Format("2006-01-02 15:04 MST")
}

func sslFormatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		days := int(d.Hours()) / 24
		h := int(d.Hours()) % 24
		if h == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd%dh", days, h)
	}
}

// sslPluralAttempts renders "attempt" / "3 attempts" so the cooldown message reads
// as a sentence at either count.
func sslPluralAttempts(n int) string {
	if n == 1 {
		return "attempt"
	}
	return fmt.Sprintf("%d attempts", n)
}
