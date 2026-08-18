package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/logger"
)

// SSLService is the entry point for everything certificate-related: the store,
// the ledger, the preflight, the acme.sh driver and the consumer fan-out.
//
// Zero-value usable and stateless, like the other services in this package, so a
// fresh copy works and callers do not have to thread a constructor through. The
// only shared mutable state is the background run below, which is package-level
// for the same reason provisionRun is (core.go:1437): issuance is single-admin and
// one-at-a-time by design, not by accident.
type SSLService struct{}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

// SSLStatus is one call that answers everything the settings page needs to render.
type SSLStatus struct {
	// Profile is the certificate this status is about, and Profiles is every one
	// that exists, so the page can render every card and the selected certificate
	// from a single call.
	Profile  string              `json:"profile"`
	Profiles []SSLProfileSummary `json:"profiles"`

	// Adoptable are certificates this host is serving that no profile owns yet,
	// which on a box deployed through deploy.sh is the normal starting state.
	Adoptable []SSLAdoptable `json:"adoptable"`

	// LegacyRenewal reports acme.sh's own cron still being installed, i.e. a second
	// scheduler renewing into a path the store does not own.
	LegacyRenewal bool `json:"legacyRenewal"`

	StoreRoot string `json:"storeRoot"`
	AcmeHome  string `json:"acmeHome"`

	// CertPath and KeyPath are the STABLE paths to put in webCertFile/webKeyFile.
	// They stay valid across every renewal and every switch, which is the whole
	// reason the store exists.
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`

	// Active describes what those paths currently resolve to, or nil when nothing
	// is managed yet.
	Active *SSLCertInfo `json:"active,omitempty"`

	// UsedByPanel / UsedBySub report whether each listener is pointed at THIS
	// profile's managed path. Both false means a renewal of it changes nothing for
	// either, which is legitimate (an inbound may be its only consumer) but is the
	// first thing to check when a renewal appears to have done nothing.
	UsedByPanel bool          `json:"usedByPanel"`
	UsedBySub   bool          `json:"usedBySub"`
	Consumers   []SSLConsumer `json:"consumers"`

	// Running is the in-flight operation, if any. While it is non-nil the UI
	// should show progress rather than an enabled button: a second request is
	// refused, not queued.
	Running *SSLRunningOp `json:"running,omitempty"`

	Budget   SSLBudget    `json:"budget"`
	Attempts []SSLAttempt `json:"attempts"`

	// Versions are the stored versions of the ACTIVE identifier set, newest
	// first, for rollback.
	Versions []string `json:"versions"`
}

// SSLRunningOp is the in-flight operation, for the "already running" case.
type SSLRunningOp struct {
	Op          string    `json:"op"`
	Identifiers []string  `json:"identifiers"`
	StartedAt   time.Time `json:"startedAt"`
	PID         int       `json:"pid"`
}

// Status gathers the full picture. Errors from the individual probes are folded
// into the result rather than returned, because a settings page that renders
// nothing because one inbound has malformed JSON is worse than one that renders
// most of the truth.
func (s *SSLService) Status(profile string) (*SSLStatus, error) {
	profile, root, err := sslResolveProfile(profile)
	if err != nil {
		return nil, err
	}
	store, err := OpenSSLStore(root)
	if err != nil {
		return nil, err
	}
	st := &SSLStatus{
		Profile:       profile,
		Profiles:      ListSSLProfiles(),
		Adoptable:     DetectAdoptableCertificates(),
		LegacyRenewal: SSLLegacyRenewalInstalled(),
		StoreRoot:     root,
		AcmeHome:      SSLAcmeHome(root),
		CertPath:      store.ActiveCertPath(),
		KeyPath:       store.ActiveKeyPath(),
	}

	if store.HasActive() {
		if info, err := store.ActiveInfo(); err == nil {
			st.Active = info
			st.Versions = store.Versions(SSLIdentifierSetKey(info.Identifiers))
		} else {
			logger.Warning("ssl: active certificate could not be parsed:", err)
		}
	}

	var ss SettingService
	if p, err := ss.GetCertFile(); err == nil {
		st.UsedByPanel = samePath(p, st.CertPath)
	}
	if p, err := ss.GetSubCertFile(); err == nil {
		st.UsedBySub = samePath(p, st.CertPath)
	}
	if consumers, err := ListSSLConsumers(st.CertPath); err == nil {
		st.Consumers = consumers
	} else {
		logger.Warning("ssl: could not list certificate consumers:", err)
	}

	if rec, ok := SSLIssuanceRunning(root); ok {
		st.Running = &rec
	}

	if ledger, err := OpenSSLLedger(SSLLedgerPath(root)); err == nil {
		st.Attempts = ledger.Attempts()
		if st.Active != nil {
			st.Budget = ledger.Budget(SSLIdentifierSetKey(st.Active.Identifiers), sslCAProduction)
		}
	} else {
		logger.Warning("ssl: ledger unavailable:", err)
	}
	return st, nil
}

// Preflight runs every local check and returns the verdict WITHOUT contacting any
// CA. Safe to call as often as the UI likes; that is the point of it.
func (s *SSLService) Preflight(profile string, req SSLPreflightRequest) (SSLPreflightResult, error) {
	_, root, err := sslResolveProfile(profile)
	if err != nil {
		return SSLPreflightResult{}, err
	}
	store, err := OpenSSLStore(root)
	if err != nil {
		return SSLPreflightResult{}, err
	}
	ledger, err := OpenSSLLedger(SSLLedgerPath(root))
	if err != nil {
		return SSLPreflightResult{}, err
	}
	var active *SSLCertInfo
	if store.HasActive() {
		active, _ = store.ActiveInfo()
	}
	return sslRunPreflight(req, active, ledger, defaultSSLPreflightDeps(root)), nil
}

// Consumers lists everything pointed at the managed certificate path, so the UI
// can show which protocols would drop connections BEFORE the operator agrees to a
// disruptive apply.
func (s *SSLService) Consumers(profile string) ([]SSLConsumer, error) {
	_, root, err := sslResolveProfile(profile)
	if err != nil {
		return nil, err
	}
	store, err := OpenSSLStore(root)
	if err != nil {
		return nil, err
	}
	return ListSSLConsumers(store.ActiveCertPath())
}

// sslResolveProfile is the one place a name coming off the wire turns into a store
// root, so every entry point validates it identically.
func sslResolveProfile(name string) (string, string, error) {
	name, err := NormalizeSSLProfile(name)
	if err != nil {
		return "", "", err
	}
	root, err := SSLProfileRoot(name)
	if err != nil {
		return "", "", err
	}
	return name, root, nil
}

// Assign points the named listeners at a profile's stable paths, and leaves every
// listener not named alone. This is what lets the panel and the subscription server
// hold different certificates: assign one profile to "panel" and another to
// "subscription", and each keeps its own identity through every later renewal,
// because both settings name a stable path that never changes again.
//
// Refuses when the profile holds nothing usable, because writing paths that do not
// resolve is precisely how web.go:541-556 ends up silently serving plain HTTP after
// the next restart. That check is the reason this cannot be a plain setting write.
func (s *SSLService) Assign(profile string, targets []string) error {
	_, root, err := sslResolveProfile(profile)
	if err != nil {
		return err
	}
	store, err := OpenSSLStore(root)
	if err != nil {
		return err
	}
	if _, err := sslValidatePair(store.ActiveCertPath(), store.ActiveKeyPath()); err != nil {
		return fmt.Errorf("that certificate is not usable yet (%w). Issue one first", err)
	}

	var panel, sub bool
	for _, t := range targets {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case SSLAssignTargetPanel:
			panel = true
		case SSLAssignTargetSub:
			sub = true
		case "":
		default:
			return fmt.Errorf("%q is not something a certificate can be assigned to", t)
		}
	}
	if !panel && !sub {
		return fmt.Errorf("pick at least one of the panel or the subscription server")
	}

	var ss SettingService
	if panel {
		if err := ss.SetCertFile(store.ActiveCertPath()); err != nil {
			return err
		}
		if err := ss.SetKeyFile(store.ActiveKeyPath()); err != nil {
			return err
		}
	}
	if sub {
		if err := ss.SetSubCertFile(store.ActiveCertPath()); err != nil {
			return err
		}
		if err := ss.SetSubKeyFile(store.ActiveKeyPath()); err != nil {
			return err
		}
	}
	return nil
}

// Unassign clears the named listeners' certificate settings, so they fall back to
// plain HTTP on the next restart.
//
// The counterpart to Assign, and it exists because the page now presents
// assignment as a switch rather than a button. A switch that only travels one way
// is a lie about the state it is drawing: with Assign alone, an operator who
// pointed the subscription server at the wrong certificate had no way back except
// pointing it at a different one.
//
// DELIBERATELY NOT VALIDATED against a store. Clearing is the one operation here
// that cannot leave a setting naming a path that does not resolve, because it
// leaves no path at all. web.go treats empty as "serve plain HTTP", which is a
// legible state; a stale path is the silent one.
//
// Nothing here restarts anything. The panel keeps serving its current certificate
// from memory until it is restarted, which gives an operator who clears the wrong
// listener the whole session to put it back.
func (s *SSLService) Unassign(targets []string) error {
	var panel, sub bool
	for _, t := range targets {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case SSLAssignTargetPanel:
			panel = true
		case SSLAssignTargetSub:
			sub = true
		case "":
		default:
			return fmt.Errorf("%q is not something a certificate can be assigned to", t)
		}
	}
	if !panel && !sub {
		return fmt.Errorf("pick at least one of the panel or the subscription server")
	}

	var ss SettingService
	if panel {
		if err := ss.SetCertFile(""); err != nil {
			return err
		}
		if err := ss.SetKeyFile(""); err != nil {
			return err
		}
	}
	if sub {
		if err := ss.SetSubCertFile(""); err != nil {
			return err
		}
		if err := ss.SetSubKeyFile(""); err != nil {
			return err
		}
	}
	return nil
}

// Rollback re-points a profile's active link at one of its stored versions. The
// version has to revalidate, so a rollback cannot be the thing that breaks TLS
// either.
func (s *SSLService) Rollback(profile, version string) error {
	_, root, err := sslResolveProfile(profile)
	if err != nil {
		return err
	}
	store, err := OpenSSLStore(root)
	if err != nil {
		return err
	}
	// Refuse a path outside the store rather than symlinking wherever we are
	// pointed: this is reachable from an HTTP handler.
	rel, err := filepath.Rel(root, filepath.Clean(version))
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("%q is not a version in this store", version)
	}
	if err := store.Activate(filepath.Clean(version)); err != nil {
		return err
	}
	ApplySSLConsumers(store.ActiveCertPath(), SSLFanOutOptions{}, func(ProvisionStep) {})
	return nil
}

// ---------------------------------------------------------------------------
// The background run
// ---------------------------------------------------------------------------

// SSLOperationRequest is one operator action.
type SSLOperationRequest struct {
	SSLIssueRequest
	FanOut SSLFanOutOptions `json:"fanOut"`

	// Profile names the certificate this operation acts on. Empty is the default
	// one, which is what every caller predating named certificates means.
	Profile string `json:"profile"`
}

// sslRun holds the single in-progress or most-recent run, so the settings page can
// poll a live log. Same shape as provisionRun (core.go:1437-1445) so the existing
// setup-console component renders it without changes.
var sslRun struct {
	mu      sync.Mutex
	running bool
	done    bool
	op      string
	steps   []ProvisionStep
	failed  bool
	summary string

	// startedAt and profile are what the current run is, so a refusal can name
	// what the caller is waiting for rather than only that they are waiting.
	startedAt time.Time
	profile   string
}

// SSLRunState is a snapshot of the background run.
type SSLRunState struct {
	Running bool            `json:"running"`
	Done    bool            `json:"done"`
	Op      string          `json:"op"`
	Steps   []ProvisionStep `json:"steps"`
	Failed  bool            `json:"failed"`
	Summary string          `json:"summary"`
}

// RunState returns the current or most-recent run's progress.
func (s *SSLService) RunState() SSLRunState {
	sslRun.mu.Lock()
	defer sslRun.mu.Unlock()
	steps := make([]ProvisionStep, len(sslRun.steps))
	copy(steps, sslRun.steps)
	return SSLRunState{
		Running: sslRun.running, Done: sslRun.done, Op: sslRun.op,
		Steps: steps, Failed: sslRun.failed, Summary: sslRun.summary,
	}
}

// Start launches an operation in the background, or refuses.
//
// REFUSES rather than queues, and the error says since when the other run has been
// going. Every operation here either costs metered CA budget or restarts a daemon,
// so a second one the operator did not knowingly start is never the right answer.
func (s *SSLService) Start(req SSLOperationRequest) error {
	// Resolve the store first, so a bad profile name is refused before anything
	// else happens.
	//
	// A CORRECTION, because this comment used to claim the opposite and someone
	// would have acted on it: the refusal below is NOT per certificate. Each
	// profile does have its own acme home, ledger and lock, and sslAcquireIssuance
	// below is per store root, but the in-memory guard that actually fires is
	// global. Issuing for the subscription name DOES block a renewal of the
	// panel's, deliberately: the standalone and IP challenges both bind port 80,
	// and two runs racing for it fail validation in the metered way.
	profileName, root, err := sslResolveProfile(req.Profile)
	if err != nil {
		return err
	}
	store, err := OpenSSLStore(root)
	if err != nil {
		return err
	}

	// ONE AT A TIME, ACROSS ALL CERTIFICATES, and that is deliberate rather than a
	// limitation of the implementation. The standalone and IP challenges both bind
	// port 80, so two issuances in flight race for it and BOTH fail validation,
	// which is the metered kind of failure (five per hour per identifier, no
	// override). Serialising is the only safe answer while any request might take
	// that path.
	//
	// Running them one after another is fully supported and shares nothing: each
	// profile has its own store root, and the acme home, the ledger and the
	// issuance lock are all derived from it.
	//
	// The message names what is running and since when. It used to say only "an SSL
	// operation is already running", which left an operator whose click did nothing
	// with no way to tell whether they had hit a stuck run or the renewal job.
	sslRun.mu.Lock()
	if sslRun.running {
		busyOp, busySince, busyFor := sslRun.op, sslRun.startedAt, sslRun.profile
		sslRun.mu.Unlock()
		if busyOp == "" {
			busyOp = "operation"
		}
		if busyFor == "" {
			busyFor = SSLDefaultProfile
		}
		return fmt.Errorf("an SSL %s for %q started at %s is still running, and only one can run at a time: two at once would race for port 80 and both would fail validation. Wait for it to finish",
			busyOp, busyFor, busySince.Local().Format("15:04:05"))
	}
	sslRun.mu.Unlock()

	// The file lock is what a separate CLI invocation of this binary also sees.
	release, err := sslAcquireIssuance(root, req.Op, req.Identifiers, time.Now)
	if err != nil {
		return err
	}

	sslRun.mu.Lock()
	sslRun.running, sslRun.done, sslRun.failed = true, false, false
	sslRun.op, sslRun.steps, sslRun.summary = req.Op, nil, ""
	sslRun.startedAt, sslRun.profile = time.Now(), profileName
	sslRun.mu.Unlock()

	go func() {
		defer release()
		emit := func(st ProvisionStep) {
			sslRun.mu.Lock()
			sslRun.steps = append(sslRun.steps, st)
			sslRun.mu.Unlock()
		}
		failed, summary := s.run(store, req, emit)
		sslRun.mu.Lock()
		sslRun.running, sslRun.done = false, true
		sslRun.failed, sslRun.summary = failed, summary
		sslRun.mu.Unlock()
	}()
	return nil
}

// run is the operation itself. Ordering is deliberate: everything free happens
// before anything metered, so a run that is going to be refused is refused before
// it can cost anything.
func (s *SSLService) run(store *SSLStore, req SSLOperationRequest, emit func(ProvisionStep)) (failed bool, summary string) {
	root := store.Root()
	setKey := SSLIdentifierSetKey(req.Identifiers)

	// A RENEWAL HAS TO BE ADDRESSED BY THE NAME acme.sh FILED IT UNDER, which is
	// the first -d it was given at issue time and not the first entry of the
	// certificate's own identifier list: that list is sorted when the certificate
	// is parsed, so a wildcard always sorts to the front and any multi-name set can
	// reorder. Getting this wrong is invisible, because acme.sh answers with the
	// same exit code it uses for "not due yet". See sslrenewname.go.
	if req.Op == SSLOpRenew {
		req.Identifiers = sslRenewIdentifiers(root, req.Identifiers)
	}

	ledger, err := OpenSSLLedger(SSLLedgerPath(root))
	if err != nil {
		emit(ProvisionStep{Name: "ledger", Msg: err.Error()})
		return true, err.Error()
	}

	// Re-apply never contacts a CA, so it skips the preflight entirely: refusing
	// it on "the certificate is still valid" would refuse the one operation whose
	// whole purpose is to run when the certificate IS still valid.
	if req.Op == SSLOpReapply {
		return s.runReapply(store, req, emit)
	}

	var active *SSLCertInfo
	if store.HasActive() {
		active, _ = store.ActiveInfo()
	}
	pre := sslRunPreflight(req.PreflightRequest(), active, ledger, defaultSSLPreflightDeps(root))
	for _, st := range pre.Steps {
		emit(st)
	}
	if pre.Blocked {
		return true, pre.Reason
	}

	// Host prerequisites. EnsureAcmeDeps is reused verbatim: acme.sh's own
	// pre-check hard-fails without a cron daemon, and --standalone needs socat or
	// python (acmedeps.go).
	emit(ProvisionStep{Name: "acme.sh dependencies", OK: true, Msg: EnsureAcmeDeps()})

	driver := newSSLAcmeDriver(root)
	if err := driver.EnsureAcmeHome(emit); err != nil {
		emit(ProvisionStep{Name: "acme home", Msg: err.Error()})
		return true, err.Error()
	}

	// Cloudflare credentials are checked BEFORE issuance because a bad token
	// fails several minutes into acme.sh in a way that reads as a DNS problem
	// (cloudflare.go:112).
	var env []string
	if req.Challenge == SSLChallengeCloudflareDNS {
		token := strings.TrimSpace(req.CloudflareToken)
		if _, err := VerifyCloudflareToken(token); err != nil {
			msg := fmt.Sprintf("The Cloudflare API token was rejected: %v. It needs Zone:DNS:Edit on this zone, and Zone:Zone:Read to be listed at all.", err)
			emit(ProvisionStep{Name: "Cloudflare token", Msg: msg})
			return true, msg
		}
		emit(ProvisionStep{Name: "Cloudflare token", OK: true, Msg: "The API token is active."})
		// In the environment, never in argv: /proc/<pid>/cmdline is world-readable.
		env = append(env, "CF_Token="+token)
	}

	// From here on the CA is involved and everything is metered.
	args, err := driver.opArgs(req.SSLIssueRequest)
	if err != nil {
		emit(ProvisionStep{Name: req.Op, Msg: err.Error()})
		return true, err.Error()
	}

	label := "issue a new certificate (spends one of 5 per 7 days for this exact set of names)"
	if req.Op == SSLOpRenew {
		label = "renew (ARI-coordinated, exempt from Let's Encrypt rate limits)"
	}
	emit(ProvisionStep{Name: "contacting Let's Encrypt", OK: true, Msg: label, Log: sslRedactArgs(args)})

	out, code, runErr := driver.exec(args, env)
	chain := driver.issuedChainPath(req.SSLIssueRequest.Primary())

	// acme.sh's RENEW_SKIP means it decided the certificate is not due and never
	// contacted the CA. Not a failure, and recording it as one would poison the
	// backoff for an operation that cost nothing.
	if req.Op == SSLOpRenew && code == sslAcmeRenewSkip {
		// TWO VERY DIFFERENT THINGS SHARE THIS EXIT CODE, and conflating them is
		// how a certificate expires while the panel reports success every six
		// hours. "Not due yet" is routine. "Not an issued domain" means the
		// renewal was addressed to a name acme.sh has no record of, so it can
		// never succeed and no amount of waiting will change that.
		if sslRenewSkipIsMisaddressed(out) {
			msg := fmt.Sprintf(
				"acme.sh has no record of %q, so it cannot renew it. The certificate is filed under the first name it was issued with; re-issue it to fix the record.",
				req.Primary())
			emit(ProvisionStep{Name: "renew", Msg: msg, Log: strings.TrimSpace(out)})
			return true, msg
		}
		emit(ProvisionStep{Name: "renew", OK: true, Warn: true,
			Msg: "acme.sh reports this certificate is not due for renewal yet, so it did not contact Let's Encrypt. Nothing was spent.",
			Log: strings.TrimSpace(out)})
		return false, "Not due for renewal; nothing was changed."
	}

	// THE GATE. On the fullchain FILE, never on the domain directory: acme.sh
	// creates the directory (with a domain key in it) even when validation fails,
	// so its presence proves nothing. vpn-ui.sh:663-681 records what gating on the
	// directory cost.
	if chain == "" {
		msg := sslExplainFailure(req.SSLIssueRequest, out, runErr)
		emit(ProvisionStep{Name: req.Op, Msg: msg, Log: strings.TrimSpace(out)})
		s.record(ledger, req.SSLIssueRequest, setKey, false, msg)
		return true, msg
	}
	s.record(ledger, req.SSLIssueRequest, setKey, true, "")
	emit(ProvisionStep{Name: req.Op, OK: true, Msg: "Let's Encrypt issued the certificate.", Log: strings.TrimSpace(out)})

	if err := s.installStageActivate(store, driver, req, setKey, emit); err != nil {
		return true, err.Error()
	}
	ApplySSLConsumers(store.ActiveCertPath(), req.FanOut, emit)
	return false, "The certificate is active."
}

// runReapply re-installs from the material already on disk and re-runs the fan-out.
// It cannot contact a CA and therefore cannot fail a rate limit, which is why it is
// the primary action: most "the certificate is not working" reports are a consumer
// holding a stale copy, not a certificate that needs reissuing.
func (s *SSLService) runReapply(store *SSLStore, req SSLOperationRequest, emit func(ProvisionStep)) (bool, string) {
	setKey := SSLIdentifierSetKey(req.Identifiers)
	driver := newSSLAcmeDriver(store.Root())

	// Best-effort: when acme.sh has the material, re-installing picks up anything
	// its own cron renewed behind our back. When it does not, the active version
	// is already the truth and only the fan-out is needed.
	if driver.issuedChainPath(req.SSLIssueRequest.Primary()) != "" {
		if err := s.installStageActivate(store, driver, req, setKey, emit); err != nil {
			emit(ProvisionStep{Name: "re-apply", OK: true, Warn: true, Msg: "Could not re-install from acme.sh (" + err.Error() + "). Continuing with the certificate already active."})
		}
	} else {
		emit(ProvisionStep{Name: "re-apply", OK: true, Msg: "No acme.sh material for these names; re-applying the certificate already active."})
	}

	if !store.HasActive() {
		msg := "There is no active managed certificate to re-apply. Issue one first."
		emit(ProvisionStep{Name: "re-apply", Msg: msg})
		return true, msg
	}
	ApplySSLConsumers(store.ActiveCertPath(), req.FanOut, emit)
	return false, "Re-applied the active certificate. No CA was contacted."
}

// installStageActivate is the promotion path: acme.sh writes into the landing
// zone, the store validates and versions it, and only then does the active link
// move.
func (s *SSLService) installStageActivate(store *SSLStore, driver *sslAcmeDriver, req SSLOperationRequest, setKey string, emit func(ProvisionStep)) error {
	_, certPath, keyPath, err := driver.sslInstallPaths(setKey)
	if err != nil {
		emit(ProvisionStep{Name: "install", Msg: err.Error()})
		return err
	}
	args, err := driver.installArgs(req.SSLIssueRequest, certPath, keyPath)
	if err != nil {
		emit(ProvisionStep{Name: "install", Msg: err.Error()})
		return err
	}
	if out, _, err := driver.exec(args, nil); err != nil {
		msg := fmt.Sprintf("acme.sh could not install the certificate: %v", err)
		emit(ProvisionStep{Name: "install", Msg: msg, Log: strings.TrimSpace(out)})
		return fmt.Errorf("%s", msg)
	}
	emit(ProvisionStep{Name: "install", OK: true, Msg: "Wrote the certificate into the managed store's landing zone."})

	version, err := store.StageFromFiles(setKey, certPath, keyPath)
	if err != nil {
		// The invariant held: nothing became active. Say so, because "issuance
		// succeeded but the panel still serves the old certificate" is otherwise
		// indistinguishable from a silent failure.
		msg := fmt.Sprintf("%v. The previously active certificate was left untouched and is still being served.", err)
		emit(ProvisionStep{Name: "validate", Msg: msg})
		return fmt.Errorf("%s", msg)
	}
	emit(ProvisionStep{Name: "validate", OK: true, Msg: "The certificate and key load together and match."})

	if err := store.Activate(version); err != nil {
		msg := fmt.Sprintf("%v. The previously active certificate was left untouched.", err)
		emit(ProvisionStep{Name: "activate", Msg: msg})
		return fmt.Errorf("%s", msg)
	}
	info, _ := store.ActiveInfo()
	detail := "The new certificate is active."
	if info != nil {
		detail = fmt.Sprintf("Active: %s, issued by %s, valid until %s (%s).",
			strings.Join(info.Identifiers, ", "), info.Issuer, sslFormatTime(info.NotAfter), sslFormatDuration(info.Remaining))
		if !info.HasIntermediates {
			// Worth its own warning: the panel works either way in a browser, but
			// stock Windows (the SSTP and IKEv2 audience) will not fetch a missing
			// issuer and fails with a message that mentions credentials, not chains.
			detail += " NOTE: the file contains no intermediate certificate, which stock Windows clients (SSTP, IKEv2) cannot work around."
		}
	}
	emit(ProvisionStep{Name: "activate", OK: true, Warn: info != nil && !info.HasIntermediates, Msg: detail})
	return nil
}

func (s *SSLService) record(ledger *SSLLedger, req SSLIssueRequest, setKey string, success bool, msg string) {
	if err := ledger.Record(SSLAttempt{
		Identifiers: req.Identifiers,
		SetKey:      setKey,
		CA:          req.CA(),
		Op:          req.Op,
		// Only the --renew path carries the RFC 9773 "replaces" field and is
		// therefore exempt from every Let's Encrypt limit. See sslacme.go.
		Exempt:  req.Op == SSLOpRenew,
		Success: success,
		Message: msg,
	}); err != nil {
		// A ledger we cannot write is a ledger that will under-count next time,
		// which is the permissive direction. Loud, because it matters.
		logger.Warning("ssl: FAILED to record an issuance attempt, the local rate-limit guard is now under-counting:", err)
	}
}

// PreflightRequest projects an issue request onto what the preflight needs, so a
// caller can run the checks for an operation it is about to start without
// restating the fields.
func (r SSLIssueRequest) PreflightRequest() SSLPreflightRequest {
	return SSLPreflightRequest{
		Identifiers: r.Identifiers,
		Challenge:   r.Challenge,
		Op:          r.Op,
		Staging:     r.Staging,
		WebrootPath: r.WebrootPath,
	}
}

// opArgs picks the invocation for the operation.
func (d *sslAcmeDriver) opArgs(req SSLIssueRequest) ([]string, error) {
	switch req.Op {
	case SSLOpIssue:
		return d.issueArgs(req)
	case SSLOpRenew:
		return d.renewArgs(req)
	default:
		return nil, fmt.Errorf("unknown operation %q", req.Op)
	}
}

// sslRedactArgs renders the command for the log. There is nothing secret in argv
// by construction (the Cloudflare token goes through the environment), so this is
// only about readability.
func sslRedactArgs(args []string) string {
	return "acme.sh " + strings.Join(args, " ")
}

// sslExplainFailure turns "acme.sh exited non-zero" into the specific thing to go
// and fix. The CA's own error names nothing actionable, and the three challenges
// fail for three completely different reasons, so one generic message would send
// the operator to the wrong place two times out of three.
func sslExplainFailure(req SSLIssueRequest, out string, err error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Let's Encrypt did not issue a certificate for %s. ", req.Primary())
	switch req.Challenge {
	case SSLChallengeCloudflareDNS:
		b.WriteString("Validation was over DNS: the API token needs Zone:DNS:Edit on THIS zone (not only on another one), and the zone has to be active in Cloudflare, meaning its nameservers are delegated there.")
	case SSLChallengeStandaloneIP:
		b.WriteString("Let's Encrypt validates an IP certificate by connecting to that address itself on TCP port 80, so it has to be this machine's own public address (not a NAT front, not a CDN) and the port has to be reachable from the internet.")
	case SSLChallengeWebroot:
		// The standalone advice below is actively wrong here: nothing of ours binds
		// port 80, so "stop whatever is holding it" would tell the operator to break
		// the very webserver this challenge depends on.
		fmt.Fprintf(&b, "acme.sh wrote the challenge file into %s/.well-known/acme-challenge/ and Let's Encrypt then fetched it over HTTP. Check that the webserver's vhost for this name really has that directory as its root (nginx `root`, apache `DocumentRoot`), that it does not intercept /.well-known/ with a rewrite or an auth rule, and that TCP port 80 is reachable from the internet.", strings.TrimRight(req.WebrootPath, "/"))
	default:
		b.WriteString("Let's Encrypt validates over HTTP: the name has to resolve to THIS server's public address and TCP port 80 has to be reachable from the internet (not firewalled, not behind a proxy for a different host).")
	}
	b.WriteString(" The certificate in use was left unchanged.")
	if err != nil {
		fmt.Fprintf(&b, " (acme.sh: %v)", err)
	}
	// Only ever one line of acme.sh output in the summary; the whole log is on the
	// step itself.
	if line := sslLastErrorLine(out); line != "" {
		fmt.Fprintf(&b, " Last error: %s", line)
	}
	return b.String()
}

func sslLastErrorLine(out string) string {
	var last string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		if strings.Contains(l, "error") || strings.Contains(l, "Error") || strings.Contains(l, "invalid") {
			last = l
		}
	}
	if len(last) > 300 {
		last = last[:300]
	}
	return last
}

// RenewIfDue renews the active certificate when it is due, and is the intended
// entry point for a scheduled job.
//
// Deliberately NOT wired to a timer here, and deliberately NOT delegated to
// acme.sh's own cron: acme.sh's `--install` cron would be a SECOND scheduler, and
// two --standalone runs racing for port 80 fail validation, which costs the
// hourly budget. One scheduler, and it is this one.
// RenewAllDue renews every certificate that is due, one profile at a time.
//
// Sequential on purpose: two --standalone runs racing for port 80 both fail
// validation and both spend budget, which is the exact failure the single-scheduler
// rule above exists to avoid. A profile that errors does not stop the others, since
// one misconfigured certificate must not park the renewal of the panel's own.
// sslRenewWaitStep and sslRenewWaitMax bound how long RenewAllDue waits for one
// certificate's run before moving to the next. The ceiling is above the acme.sh
// exec timeout so a run that is genuinely working is never abandoned, and finite so
// a wedged run cannot stall the whole tick forever.
const (
	sslRenewWaitStep = 2 * time.Second
	sslRenewWaitMax  = 30 * time.Minute
)

// sslWaitForRun blocks until the background run finishes, or the ceiling passes.
// Reports whether it actually finished.
func (s *SSLService) sslWaitForRun() bool {
	deadline := time.Now().Add(sslRenewWaitMax)
	for time.Now().Before(deadline) {
		if !s.RunState().Running {
			return true
		}
		time.Sleep(sslRenewWaitStep)
	}
	return false
}

func (s *SSLService) RenewAllDue() error {
	var firstErr error
	for _, p := range ListSSLProfiles() {
		// The auto-renew switch is honoured HERE, on the unattended path, and
		// nowhere else. Renew from the row menu is an operator asking for it, and
		// must keep working on a certificate whose scheduling they turned off:
		// "do not renew this on your own" is a different statement from "never
		// renew this".
		if !p.AutoRenew {
			logger.Debug("ssl: auto renew is off for", p.Name, "- skipping it")
			continue
		}
		if err := s.RenewIfDue(p.Name); err != nil {
			logger.Warning("ssl: renewing certificate ", p.Name, ": ", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// WAIT FOR IT BEFORE STARTING THE NEXT ONE. RenewIfDue ends in Start,
		// which returns as soon as the background goroutine is launched, and only
		// one run is allowed at a time across all certificates. Without this the
		// loop raced ahead and every profile after the first was refused
		// milliseconds later, logged as a warning and simply not renewed: at most
		// ONE certificate renewed per six-hourly tick, so N due certificates took
		// roughly 6N hours to converge.
		//
		// Invisible on 90-day certificates, whose renewal window is thirty days.
		// Not invisible on a Let's Encrypt IP certificate, which lives 160 hours
		// and has a 53-hour window: a host holding two of those could miss one
		// entirely. Taking over the shell flows' certificates made multi-profile
		// hosts the normal case rather than the exception, which is what turned
		// this from theoretical into likely.
		if !s.sslWaitForRun() {
			logger.Warning("ssl: the renewal of", p.Name, "is still running after",
				sslRenewWaitMax, "- leaving the rest of this pass for the next tick")
			return firstErr
		}
	}
	return firstErr
}

func (s *SSLService) RenewIfDue(profile string) error {
	profileName, root, err := sslResolveProfile(profile)
	if err != nil {
		return err
	}
	store, err := OpenSSLStore(root)
	if err != nil {
		return err
	}
	if !store.HasActive() {
		return nil
	}
	info, err := store.ActiveInfo()
	if err != nil {
		return err
	}
	if !info.RenewalDue {
		return nil
	}
	if err := sslCheckMinAge(info, time.Now()); err != nil {
		logger.Warning("ssl: skipping an automatic renewal:", err)
		return nil
	}
	// The challenge here is INERT and is not worth improving. On a renew,
	// renewArgs sends only `--home --config-home --server --renew -d <primary>`
	// and acme.sh replays what it recorded at issue time; the preflight resolves
	// the real one from acme.sh's own conf (sslResolveRenewChallenge). It is set
	// only because the field exists. A renewal that genuinely needs a DIFFERENT
	// challenge is not a renewal: it is an --issue, and it costs an exact-set slot.
	challenge := SSLChallengeStandaloneDomain
	if len(info.IPAddresses) > 0 && len(info.DNSNames) == 0 {
		challenge = SSLChallengeStandaloneIP
	}
	req := SSLOperationRequest{SSLIssueRequest: SSLIssueRequest{
		Identifiers: info.Identifiers,
		Challenge:   challenge,
		Op:          SSLOpRenew,
	}, Profile: profileName}

	// Check BEFORE starting, so a scheduled renewal that is going to be refused
	// stays silent instead of clobbering the run log.
	//
	// Starting it anyway costs no budget (the run dies in the preflight without
	// contacting the CA and without a ledger entry), but Start resets sslRun, so
	// an operator who ran something by hand would come back to a "recent failures"
	// block from a timer they never triggered, replacing the output they were
	// reading. This belongs here rather than in the job: the job cannot know which
	// refusals are routine, and every caller of RenewIfDue wants the same silence.
	pre, err := s.Preflight(profileName, req.PreflightRequest())
	if err != nil {
		return err
	}
	if pre.Blocked {
		logger.Info("ssl: automatic renewal not attempted:", pre.Reason)
		return nil
	}
	return s.Start(req)
}

// SSLStoreExists reports whether anything has been issued into the managed store,
// so the UI can show an empty state rather than an error on a fresh install.
func SSLStoreExists() bool {
	_, err := os.Stat(filepath.Join(DefaultSSLStoreRoot(), sslVersionsDir))
	return err == nil
}
