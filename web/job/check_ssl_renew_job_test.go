package job

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xuilogger "github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/op/go-logging"
	"github.com/robfig/cron/v3"
)

// Every test here is offline by construction: the only path to a CA is
// SSLService.RenewIfDue, and each test either proves the job did not reach it or
// substitutes for it. Nothing below issues, renews or resolves anything.

// newSSLJobStoreRoot points the managed SSL store at a temp dir and returns its
// root. The env var is read on every DefaultSSLStoreRoot call, so this cannot
// leak into the developer's own bin/cert/managed and cannot touch a real
// certificate.
func newSSLJobStoreRoot(t *testing.T) string {
	t.Helper()
	// logger is a nil global until InitLogger runs, and the job logs on every path
	// that matters here (see the note in check_client_ip_job_integration_test.go).
	// Without this a test would "pass" a panic assertion by panicking in the logger.
	t.Setenv("VPNUI_LOG_FOLDER", t.TempDir())
	loggerInitOnce.Do(func() { xuilogger.InitLogger(logging.ERROR) })

	t.Setenv("VPNUI_DB_FOLDER", t.TempDir())
	return service.DefaultSSLStoreRoot()
}

func TestCheckSSLRenewJob_DoesNothingWhenNoCertificateIsManaged(t *testing.T) {
	root := newSSLJobStoreRoot(t)

	j := NewCheckSSLRenewJob()
	called := false
	j.renew = func() error { called = true; return nil }

	skipped, err := j.tick()
	if err != nil {
		t.Fatalf("a panel with no managed certificate is not an error state: %v", err)
	}
	if called {
		t.Fatal("the job reached the service layer on a panel that never used the SSL manager")
	}
	if skipped == "" {
		t.Fatal("expected a skip reason so the log says why nothing happened")
	}

	// The stronger half of "no-op": RenewIfDue would have CREATED the store, because
	// OpenSSLStore creates the layout it is handed. SSLStoreExists is what the
	// settings page uses to choose its empty state, so a tick that materialised the
	// store would change the UI on a panel that holds no certificate at all.
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("the job created the store root %s (stat err: %v)", root, err)
	}
	if service.SSLStoreExists() {
		t.Fatal("the job made SSLStoreExists true without a certificate ever being issued")
	}
}

func TestCheckSSLRenewJob_SkipsWhileTheIssuanceLockIsHeld(t *testing.T) {
	root := newSSLJobStoreRoot(t)
	// A store that exists but holds nothing, so the tick gets past the store check
	// and the lock is the thing under test.
	if _, err := service.OpenSSLStore(root); err != nil {
		t.Fatalf("OpenSSLStore: %v", err)
	}

	// The on-disk shape of service's issuance lock (sslacme.go). Our own pid, so its
	// liveness check sees a process that is genuinely running.
	lock, err := json.Marshal(map[string]any{
		"pid":         os.Getpid(),
		"startedAt":   time.Now(),
		"op":          "issue",
		"identifiers": []string{"vpn.example.com"},
	})
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "issuance.lock"), lock, 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	if _, running := service.SSLIssuanceRunning(root); !running {
		t.Fatal("setup: the lock file should read as held, the rest of this test proves nothing otherwise")
	}

	j := NewCheckSSLRenewJob()
	called := false
	j.renew = func() error { called = true; return nil }

	skipped, err := j.tick()
	if err != nil {
		t.Fatalf("a held lock is a skip, not a failure: %v", err)
	}
	if called {
		t.Fatal("the job started a renewal while an issuance was already running: two acme.sh --standalone runs race for port 80 and BOTH fail validation")
	}
	if !strings.Contains(skipped, "issue") {
		t.Fatalf("the skip reason should name the operation holding the lock, got %q", skipped)
	}
}

func TestCheckSSLRenewJob_RunSurvivesAFailingServiceCall(t *testing.T) {
	root := newSSLJobStoreRoot(t)
	if _, err := service.OpenSSLStore(root); err != nil {
		t.Fatalf("OpenSSLStore: %v", err)
	}

	j := NewCheckSSLRenewJob()
	j.renew = func() error { return errors.New("acme home is not writable") }
	j.Run() // Logged, not propagated. Reaching the next line IS the assertion.

	// The harder one. The scheduler is built without cron.Recover, so a panic that
	// escapes Run does not fail this tick, it kills the panel: web server, Xray
	// supervision, RADIUS and all. A failure here crashes the test binary rather
	// than reporting, which is the point.
	j.renew = func() error { panic("nil map write in the ledger") }
	j.Run()
}

func TestSSLRenewScheduleIsInTheSafeBand(t *testing.T) {
	// Parsed with the same options web.go builds the scheduler with (cron.WithSeconds
	// plus descriptors), so a spec that would be rejected at startup fails here
	// instead of at 03:00 on somebody's server.
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	sched, err := parser.Parse(SSLRenewSchedule)
	if err != nil {
		t.Fatalf("SSLRenewSchedule %q does not parse: %v", SSLRenewSchedule, err)
	}

	// Truncated because cron's constant-delay schedule drops the sub-second part of
	// the first tick, which would otherwise make the two gaps differ by nanoseconds.
	start := time.Now().Truncate(time.Second)
	first := sched.Next(start)
	interval := first.Sub(start)
	if got := sched.Next(first).Sub(first); got != interval {
		t.Fatalf("the schedule is not a fixed interval: %s then %s", interval, got)
	}

	// FLOOR: the ledger's per-failure backoff tops out at an hour (sslledger.go). A
	// tick inside that window can only ever be refused by the cooldown, and each
	// refusal still starts a run and overwrites the log the operator is reading.
	const maxLedgerBackoff = time.Hour
	if interval <= maxLedgerBackoff {
		t.Fatalf("interval %s is not clear of the ledger's %s failure backoff: ticks would be spent on refusals", interval, maxLedgerBackoff)
	}

	// CEILING: the shortest certificate this panel can hold is a Let's Encrypt IP
	// certificate on the shortlived profile, and renewal is due with a third of its
	// lifetime left, so this is the whole window a renewal has to happen in. Four
	// attempts is the minimum worth having: one transient DNS or port-80 failure
	// must not exhaust it.
	const shortlivedLifetime = 160 * time.Hour
	renewWindow := shortlivedLifetime / 3
	if attempts := renewWindow / interval; attempts < 4 {
		t.Fatalf("interval %s leaves only %d attempts inside the %s renewal window of a shortlived IP certificate", interval, attempts, renewWindow)
	}
}

func TestSSLRenewJobIsRegisteredWithTheScheduler(t *testing.T) {
	// The bug this whole job exists to fix was a complete, tested, documented
	// service entry point that nothing ever called. A job nobody schedules is the
	// same bug wearing a different hat, and no other test in this package would
	// notice it, so this one reads the registration site directly.
	src, err := os.ReadFile(filepath.Join("..", "web.go"))
	if err != nil {
		t.Fatalf("read web/web.go: %v", err)
	}
	for _, want := range []string{"job.NewCheckSSLRenewJob()", "job.SSLRenewSchedule", "job.SSLRenewStartupDelay"} {
		if !strings.Contains(string(src), want) {
			t.Fatalf("web/web.go no longer references %s, so the managed certificate never renews itself. Keep the registration in startTask", want)
		}
	}
}
