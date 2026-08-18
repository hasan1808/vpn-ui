package job

import (
	"fmt"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/service"
)

const (
	// SSLRenewSchedule is how often the renewal check runs, and both the floor and
	// the ceiling on it are real.
	//
	// The CEILING is the shortest certificate this panel can hold. A Let's Encrypt
	// IP certificate is issued under the shortlived profile and lives 160 hours,
	// and the store calls a renewal due with a third of the lifetime left
	// (sslstore.go:435), so the entire window in which that renewal can happen is
	// 53 hours. A daily tick would give that window two attempts and one transient
	// DNS failure would spend both. Six hours gives it eight, and gives a 90-day
	// certificate's 30-day window more than a hundred.
	//
	// The FLOOR is the ledger's per-failure backoff, which tops out at 60 minutes
	// (sslledger.go:103). A shorter interval would produce ticks that can only be
	// refused by the cooldown, and each refusal still overwrites the live log the
	// operator is watching. At six hours the backoff has always expired by the next
	// tick, so a failing renewal retries at most four times a day: well inside Let's
	// Encrypt's 5-failed-validations-per-hour bucket, and it leaves that bucket with
	// room for the operator to test by hand.
	SSLRenewSchedule = "@every 6h"

	// SSLRenewStartupDelay is when the first check runs after the panel starts.
	//
	// Needed because robfig/cron schedules an "@every" job one full interval AFTER
	// the scheduler starts: with no startup run, a host that reboots more often than
	// six hours would never renew at all, and a VM that was powered off past its
	// renewal date would sit on an expired certificate for six hours after coming
	// back. Five minutes rather than immediately, because startTask is still
	// bringing up every protocol and restarting Xray, and the standalone challenge
	// needs port 80 free and DNS working, neither of which is settled in the first
	// seconds of a boot.
	SSLRenewStartupDelay = 5 * time.Minute
)

// CheckSSLRenewJob renews the managed certificate when it comes due.
//
// This is the ONLY renewal scheduler on the box, deliberately. acme.sh's own
// `--install` cron was never installed (sslmanager.go:571), because two schedulers
// each running `--standalone` race for port 80 and BOTH fail validation, and a
// failed validation is metered at 5 per hour per identifier with no override form.
// So if this job goes away, nothing renews; and if a second one appears, renewals
// start failing.
type CheckSSLRenewJob struct {
	sslService service.SSLService

	// renew overrides the service call, for tests that must not go anywhere near a
	// CA. Nil in production, so the zero-value job behaves like every other job in
	// this package.
	renew func() error
}

// NewCheckSSLRenewJob creates a new certificate renewal job.
func NewCheckSSLRenewJob() *CheckSSLRenewJob {
	return new(CheckSSLRenewJob)
}

// Run renews the active managed certificate if it is due, and does nothing at all
// otherwise.
//
// Thin on purpose: every real decision (whether one is due, whether it is old
// enough, whether the last attempt failed recently, whether the request takes the
// rate-limit-exempt path) lives in SSLService.RenewIfDue and the preflight behind
// it, so that this job and the button on the settings page cannot drift into two
// different sets of rules.
func (j *CheckSSLRenewJob) Run() {
	// The scheduler is built without cron.Recover (web.go:532), so a panic in here
	// takes the whole panel down rather than just this tick. Worth guarding for what
	// this job touches: certificate and lock files on disk that the panel did not
	// necessarily write itself.
	defer func() {
		if r := recover(); r != nil {
			logger.Error("ssl: the renewal job panicked, the certificate was NOT renewed:", r)
		}
	}()

	skipped, err := j.tick()
	switch {
	case err != nil:
		// Warning rather than Error: the certificate in use is untouched either way,
		// and the reason matters because the next attempt is six hours out.
		logger.Warning("ssl: the scheduled renewal did not start:", err)
	case skipped != "":
		logger.Debug("ssl: skipping the scheduled renewal check,", skipped)
	default:
		// Silence is the normal outcome, so say something only when a run actually
		// started. Read back off the issuance lock rather than inferring it: Start
		// returns as soon as the background run is launched, so a nil error means
		// "started", not "renewed", and only the lock can tell those apart from a
		// tick where nothing was due.
		if op, running := service.SSLIssuanceRunning(service.DefaultSSLStoreRoot()); running {
			logger.Info("ssl: the certificate for", strings.Join(op.Identifiers, ", "), "is due, renewing it in the background")
		}
	}
}

// tick is Run without the logging, so the skip paths can be asserted in a test
// with no CA anywhere near them. A non-empty reason means nothing was attempted.
func (j *CheckSSLRenewJob) tick() (skipped string, err error) {
	// Nothing managed, nothing to do. This has to come FIRST and cannot be folded
	// into RenewIfDue: RenewIfDue opens the store, and OpenSSLStore CREATES the
	// layout it is handed (sslstore.go:102), including the versions directory that
	// SSLStoreExists tests for. So on a panel that never used the SSL manager, one
	// tick of a job that skipped this check would flip the settings page out of its
	// empty state forever, without a certificate ever existing.
	if !service.SSLStoreExists() {
		return "no certificate is managed on this panel", nil
	}

	// Somebody already holds the issuance slot: an operator issuing from the
	// settings page, or a previous tick of this job still running. Skip, never
	// queue, for the same reason acme.sh's cron is not installed. Start would refuse
	// this anyway, so the only thing this check buys is skipping quietly instead of
	// logging a refusal as a failure every six hours.
	root := service.DefaultSSLStoreRoot()
	if op, running := service.SSLIssuanceRunning(root); running {
		return fmt.Sprintf("an SSL %s for %s has been running since %s (pid %d)",
			op.Op, strings.Join(op.Identifiers, ", "),
			op.StartedAt.Local().Format("15:04"), op.PID), nil
	}

	return "", j.renewIfDue()
}

// renewIfDue is the one call into the service layer, indirected only so a test can
// stand in for it.
func (j *CheckSSLRenewJob) renewIfDue() error {
	if j.renew != nil {
		return j.renew()
	}
	// Every named certificate, not just the default one: a subscription certificate
	// nobody renews expires exactly as quietly as the panel's would.
	return j.sslService.RenewAllDue()
}
