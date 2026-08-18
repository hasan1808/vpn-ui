package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/logger"
)

// The acme.sh driver, and the lock that keeps exactly one issuance in flight.
//
// Three facts about the bundled acme.sh 3.1.4 shape everything below, and each one
// was read out of build/acme/acme.sh rather than assumed:
//
//  1. There is NO --dry-run. Zero occurrences in the source. Every safety check has
//     to be built locally, which is what sslpreflight.go and sslledger.go are.
//  2. DEFAULT_CA=$CA_ZEROSSL (acme.sh:37). Omitting --server does not go to Let's
//     Encrypt, it goes to ZeroSSL, quietly. --server is passed on every invocation.
//  3. The RFC 9773 "replaces" field, which is what makes a renewal exempt from
//     every Let's Encrypt rate limit, is sent ONLY when _ACME_IS_RENEW=1
//     (acme.sh:5155). That flag is set by the --renew path and by nothing else; the
//     comment there says outright that --issue, even with --force, is not a
//     renewal. So --renew is free and --issue costs budget, and the two are
//     modelled here as different operations rather than as one operation with a
//     flag.

const (
	// sslAcmeHomeDir is the pinned ACME home inside the certificate store.
	//
	// PINNING IT IS THE POINT. Today the scripts rely on $HOME/.acme.sh, and the
	// systemd unit (systemd.go:79-82) sets User=root with no Environment=HOME, so
	// where that lands depends on how the panel was started: a systemd start and a
	// manual start can genuinely use different directories, which means different
	// account keys and different per-domain state for the same host. Pinning makes
	// it deterministic, lets an uninstall clean it up (it leaks today, since
	// uninstall.go:384-386 removes only the cert dir), and puts the ACME account
	// key somewhere a backup can be told about.
	sslAcmeHomeDir = "acme"

	// sslInstallDir is the landing zone --install-cert writes into, one stable
	// directory per identifier set.
	//
	// Stable rather than temporary because acme.sh records these paths in the
	// per-domain conf and reuses them on a later --renew. Separate from the version
	// store because of the trap recorded at vpn-ui.sh:663-681: --install-cert can
	// die partway and leave a partial key behind, so it must never write anywhere
	// that is served. Everything here is unvalidated until Stage promotes it.
	sslInstallDir = "install"

	sslLockFileName = "issuance.lock"

	// sslLockStaleAfter bounds a wedged run. acme.sh --standalone on a firewalled
	// port 80 waits for a validation that never arrives, and without a timeout that
	// one run would wedge the whole feature permanently. Generous, because breaking
	// the lock on a run that is merely slow (DNS-01 propagation waits are minutes)
	// would let a second acme.sh race the first for port 80, and two racing
	// standalone servers produce validation FAILURES, which is the expensive kind.
	sslLockStaleAfter = 30 * time.Minute

	// sslAcmeTimeout kills the child before the lock goes stale, so the lock is
	// always released by the owner rather than broken by the next caller.
	//
	// LONGER THAN acme.sh's OWN DNS WINDOW, and that is the whole reason for the
	// value. _check_dns_entries polls for the challenge TXT record for up to 20
	// minutes (acme.sh:4700). At the previous 15 minutes this timeout fired FIRST
	// on any zone slow to propagate, and killing acme.sh mid-poll means it never
	// reaches dns_cf_rm, so the _acme-challenge records it created are left behind
	// in the zone, one pair per attempt, accumulating with every retry.
	//
	// Only DNS-01 runs anywhere near this long, so in practice this was a
	// wildcard-only defect: a wildcard has no other validation method available.
	// 25 minutes covers the full poll plus the issuance and the cleanup after it,
	// and sslLockStaleAfter stays strictly greater so the invariant above holds.
	sslAcmeTimeout = 25 * time.Minute

	// sslAcmeRenewSkip is acme.sh's RENEW_SKIP (acme.sh:93): --renew decided the
	// certificate is not due yet and returned WITHOUT contacting the CA. Benign,
	// costs nothing, and must not be recorded as a failure.
	sslAcmeRenewSkip = 2
)

// SSLAcmeHome is the pinned ACME home for a store root.
func SSLAcmeHome(storeRoot string) string { return filepath.Join(storeRoot, sslAcmeHomeDir) }

// SSLAcmeScript is the acme.sh the panel drives.
func SSLAcmeScript(storeRoot string) string { return filepath.Join(SSLAcmeHome(storeRoot), "acme.sh") }

// ---------------------------------------------------------------------------
// The issuance lock
// ---------------------------------------------------------------------------

// sslLockRecord is what the lock file holds. The PID and the start time are both
// recorded because neither alone is enough: a start time cannot tell a wedged run
// from a crashed one, and a PID can be recycled.
type sslLockRecord struct {
	PID         int       `json:"pid"`
	StartedAt   time.Time `json:"startedAt"`
	Op          string    `json:"op"`
	Identifiers []string  `json:"identifiers"`
}

// sslLockMu serialises the read-modify-write of the lock file within this
// process. The file itself is what makes the lock visible to a separate CLI
// invocation of the same binary.
var sslLockMu sync.Mutex

// sslAcquireIssuance takes the single issuance slot, or refuses immediately.
//
// REFUSES, never queues. A queued second issuance is a second CA request the
// operator did not knowingly ask for, and every CA request here is metered. The
// shape mirrors StartProvision (core.go:1454), which already gets refuse-if-running
// right for the same reason.
func sslAcquireIssuance(storeRoot, op string, identifiers []string, now func() time.Time) (release func(), err error) {
	sslLockMu.Lock()
	defer sslLockMu.Unlock()

	path := filepath.Join(storeRoot, sslLockFileName)
	if rec, ok := sslReadLock(path); ok {
		age := now().Sub(rec.StartedAt)
		alive := sslProcessAlive(rec.PID)
		if age < sslLockStaleAfter && alive {
			return nil, fmt.Errorf("issuance already running since %s (%s for %s, pid %d). Wait for it to finish: starting a second one would race it for port 80 and both would fail validation",
				rec.StartedAt.Local().Format("15:04"), rec.Op, strings.Join(rec.Identifiers, ", "), rec.PID)
		}
		// Breaking a lock is worth a log line: if it happens repeatedly, the run
		// is wedging every time and that is the actual problem to chase.
		reason := "the process is gone"
		if alive {
			// A recycled PID can make a dead run look alive, which is why the
			// timeout exists as an independent condition rather than as a
			// fallback.
			reason = fmt.Sprintf("it has been running for %s", sslFormatDuration(age))
		}
		logger.Warning("ssl: breaking a stale issuance lock from pid", rec.PID, "-", reason)
	}

	rec := sslLockRecord{PID: os.Getpid(), StartedAt: now(), Op: op, Identifiers: identifiers}
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := backend.WriteFileAtomic(path, data, 0o600); err != nil {
		return nil, fmt.Errorf("ssl: take issuance lock: %w", err)
	}
	var once sync.Once
	return func() { once.Do(func() { _ = os.Remove(path) }) }, nil
}

// SSLIssuanceRunning reports the in-flight issuance, if any, for the UI to show
// instead of an enabled button. It returns the exported SSLRunningOp rather than
// the on-disk lock record, so a caller outside this package can name the type it
// gets back, and so this and SSLStatus.Running are the same shape.
func SSLIssuanceRunning(storeRoot string) (SSLRunningOp, bool) {
	rec, ok := sslReadLock(filepath.Join(storeRoot, sslLockFileName))
	if !ok {
		return SSLRunningOp{}, false
	}
	if time.Since(rec.StartedAt) >= sslLockStaleAfter || !sslProcessAlive(rec.PID) {
		return SSLRunningOp{}, false
	}
	return SSLRunningOp{
		Op:          rec.Op,
		Identifiers: rec.Identifiers,
		StartedAt:   rec.StartedAt,
		PID:         rec.PID,
	}, true
}

func sslReadLock(path string) (sslLockRecord, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return sslLockRecord{}, false
	}
	var rec sslLockRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		// An unreadable lock file cannot be honoured, and treating it as held
		// would wedge the feature with no way out from the UI.
		return sslLockRecord{}, false
	}
	return rec, rec.PID > 0
}

// sslProcessAlive asks the kernel whether the PID exists. Signal 0 performs the
// permission and existence checks without delivering anything, so EPERM (someone
// else's process) still means alive.
func sslProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

// SSLIssueRequest is one operation against a CA.
type SSLIssueRequest struct {
	// Identifiers in the operator's own order. The FIRST one is the name acme.sh
	// files the certificate under and the one every later --renew and
	// --install-cert addresses it by, so the order here is load-bearing and is
	// deliberately NOT the sorted order the ledger keys on.
	Identifiers []string `json:"identifiers"`

	Challenge string `json:"challenge"`
	Op        string `json:"op"`
	Staging   bool   `json:"staging"`
	Email     string `json:"email"`

	// KeyType is the certificate's key algorithm, as one of the SSLKey* values.
	// Empty means RSA-2048, which is what every certificate issued before this
	// field existed got.
	//
	// ISSUE ONLY. acme.sh records the choice in the per-domain conf as
	// Le_Keylength and reads it back on --renew (acme.sh:6257-6260), so a renewal
	// keeps the algorithm on its own and the panel does not have to store it.
	KeyType string `json:"keyType"`

	// CloudflareToken is used only by the DNS-01 path and is passed to acme.sh in
	// the ENVIRONMENT, never in argv: a command line is world-readable through
	// /proc/<pid>/cmdline and an environment is not. CF_Token is also the variable
	// acme.sh's own dns_cf hook reads.
	CloudflareToken string `json:"-"`

	// ListenV6 forces acme.sh's standalone server onto IPv6. Not cosmetic: without
	// an explicit --listen-v4/--listen-v6 the standalone server is a bare socat
	// TCP-LISTEN that comes up IPv6-only, and Let's Encrypt's IPv4 fetch then gets
	// connection-refused with nothing in the log to explain it.
	ListenV6 bool `json:"listenV6"`

	// WebrootPath is the document root for SSLChallengeWebroot: the directory an
	// EXISTING webserver already publishes, into which acme.sh writes
	// .well-known/acme-challenge/<token>. Ignored by every other challenge.
	//
	// acme.sh records it in the per-domain conf as Le_Webroot, which is how a later
	// --renew knows to use the same directory without being told again, and how the
	// preflight's renew resolver recognises a webroot certificate.
	WebrootPath string `json:"webrootPath"`
}

// Primary is the name acme.sh files the certificate under.
func (r SSLIssueRequest) Primary() string {
	for _, id := range r.Identifiers {
		if s := strings.TrimSpace(id); s != "" {
			return s
		}
	}
	return ""
}

// CA names the namespace this request goes to, for the ledger.
func (r SSLIssueRequest) CA() string {
	if r.Staging {
		return sslCAStaging
	}
	return sslCAProduction
}

// sslRunFunc is the exec seam. Every test drives this instead of a real acme.sh.
type sslRunFunc func(ctx context.Context, bin string, args, env []string) (string, int, error)

type sslAcmeDriver struct {
	storeRoot string
	run       sslRunFunc
}

func newSSLAcmeDriver(storeRoot string) *sslAcmeDriver {
	return &sslAcmeDriver{storeRoot: storeRoot, run: sslRunCommand}
}

func sslRunCommand(ctx context.Context, bin string, args, env []string) (string, int, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return string(out), code, err
}

// EnsureAcmeHome creates the pinned home, puts the bundled acme.sh 3.1.4 and its
// Cloudflare hook in it, and adopts an existing account if there is one.
//
// The script is extracted by re-running THIS binary as `vpn-ui install-acme`
// (main.go:1407-1425) rather than by embedding it a second time: go:embed cannot
// reach build/acme from web/service, and the CLI already writes both the script and
// dnsapi/dns_cf.sh into the right relative layout. acme.sh's own _findHook looks in
// $_SCRIPT_HOME/dnsapi first, and $_SCRIPT_HOME is the directory acme.sh itself
// lives in, so that layout is exactly what the Cloudflare path needs.
//
// acme.sh's `--install` is deliberately NOT run. All it adds is a cron entry and a
// copy into $HOME, and this panel schedules its own renewals; installing its cron
// would mean two schedulers, and two --standalone runs racing for port 80 fail
// validation, which is the expensive kind of failure.
func (d *sslAcmeDriver) EnsureAcmeHome(emit func(ProvisionStep)) error {
	home := SSLAcmeHome(d.storeRoot)

	// acme.sh refuses a home containing a space, by name, at acme.sh:2986. Caught
	// here so the message points at the path rather than at a shell error.
	if strings.ContainsAny(home, " \t") {
		return fmt.Errorf("the certificate store path %q contains a space, which acme.sh rejects for --home. Move the install to a path without spaces", home)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fmt.Errorf("create acme home %s: %w", home, err)
	}

	script := SSLAcmeScript(d.storeRoot)
	if fi, err := os.Stat(script); err != nil || fi.Size() == 0 {
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate this binary to extract the bundled acme.sh: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, _, err := d.run(ctx, self, []string{"install-acme", script}, nil)
		if err != nil {
			return fmt.Errorf("extract the bundled acme.sh: %w (%s)", err, strings.TrimSpace(out))
		}
		emit(ProvisionStep{Name: "acme.sh", OK: true, Msg: "Installed the bundled acme.sh 3.1.4 into " + home, Log: strings.TrimSpace(out)})
	} else {
		emit(ProvisionStep{Name: "acme.sh", OK: true, Msg: "Using the pinned acme.sh at " + script})
	}
	_ = os.Chmod(script, 0o755)

	emit(d.adoptLegacyAccount())
	return nil
}

// adoptLegacyAccount copies an existing ACME account from $HOME/.acme.sh into the
// pinned home, so an operator who already issued certificates through the installer
// is not silently registered a second time.
//
// The ACCOUNT files only: account.conf, the account key, and the ca/ tree. The
// per-domain directories are deliberately left where they are. Copying those would
// give two acme homes that each believe they own the domain and each schedule a
// renewal, and two --standalone runs racing for port 80 produce validation
// failures. The cost of not copying them is one --issue (one exact-set slot) to
// bootstrap a previously-issued name into the managed home, which is a single
// known charge instead of an open-ended source of failures.
//
// Worth saying plainly: losing ACME account state does NOT reset any Let's Encrypt
// counter. The exact-set new-certificate limit is not account-scoped at all, so a
// fresh account starts with exactly the budget the old one had left.
func (d *sslAcmeDriver) adoptLegacyAccount() ProvisionStep {
	home := SSLAcmeHome(d.storeRoot)
	if _, err := os.Stat(filepath.Join(home, "account.conf")); err == nil {
		return ProvisionStep{Name: "acme account", OK: true, Msg: "Using the ACME account already in the managed home."}
	}
	legacy := filepath.Join(sslHomeDir(), ".acme.sh")
	if _, err := os.Stat(filepath.Join(legacy, "account.conf")); err != nil {
		return ProvisionStep{Name: "acme account", OK: true, Msg: "No previous ACME account found; one will be registered on first use."}
	}

	var copied []string
	for _, name := range []string{"account.conf", "account.key", "ca"} {
		src := filepath.Join(legacy, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := sslCopyPath(src, filepath.Join(home, name)); err != nil {
			return ProvisionStep{Name: "acme account", OK: true, Warn: true, Msg: fmt.Sprintf(
				"Could not adopt the existing ACME account from %s (%v). A new account will be registered, which costs nothing: Let's Encrypt's per-name limits are not reset or shared by account.", legacy, err)}
		}
		copied = append(copied, name)
	}
	if len(copied) == 0 {
		return ProvisionStep{Name: "acme account", OK: true, Msg: "No previous ACME account found; one will be registered on first use."}
	}
	return ProvisionStep{Name: "acme account", OK: true, Msg: fmt.Sprintf(
		"Adopted the existing ACME account from %s (%s). Its per-domain certificates were left in place so the old install's renewals keep working.",
		legacy, strings.Join(copied, ", "))}
}

// sslHomeDir resolves $HOME the way the shell scripts do. Under systemd, User=root
// with no Environment=HOME (systemd.go:79-82) means HOME may be unset or "/", which
// is exactly the non-determinism the pinned home exists to end; here it only
// affects where an OLD account is looked for, so /root is the sensible fallback.
func sslHomeDir() string {
	if h := os.Getenv("HOME"); h != "" && h != "/" {
		return h
	}
	return "/root"
}

func sslCopyPath(src, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		return backend.WriteFileAtomic(dst, data, fi.Mode().Perm())
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, e := range entries {
		if err := sslCopyPath(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// baseArgs are the flags every invocation carries.
func (d *sslAcmeDriver) baseArgs(req SSLIssueRequest) []string {
	home := SSLAcmeHome(d.storeRoot)
	args := []string{"--home", home, "--config-home", home}

	// THE SERVER, AND WHY --staging IS NEVER PASSED.
	//
	// acme.sh only consults --staging when ACME_DIRECTORY is still empty
	// (acme.sh:3123). --server runs _selectServer at the end of argument parsing
	// (acme.sh:9016-9018), which SETS and exports ACME_DIRECTORY. So `--server
	// letsencrypt --staging` reaches PRODUCTION while the operator believes it went
	// to staging, and the tell is a real certificate and a spent exact-set slot.
	// The staging directory has its own name in CA_NAMES (acme.sh:43), so selecting
	// it by server name is unambiguous and cannot be overridden by the other flag.
	if req.Staging {
		args = append(args, "--server", "letsencrypt_test")
	} else {
		args = append(args, "--server", "letsencrypt")
	}
	if email := strings.TrimSpace(req.Email); email != "" {
		args = append(args, "--accountemail", email)
	}
	return args
}

// issueArgs builds the --issue invocation. Never --force: forcing does not make an
// issuance a renewal (acme.sh:5155 again) so it cannot save budget, and its only
// real effect is to spend a slot the operator was being protected from.
func (d *sslAcmeDriver) issueArgs(req SSLIssueRequest) ([]string, error) {
	primary := req.Primary()
	if primary == "" {
		return nil, errors.New("no identifier given")
	}
	args := append(d.baseArgs(req), "--issue", "-d", primary)
	for _, id := range req.Identifiers[1:] {
		if s := strings.TrimSpace(id); s != "" && s != primary {
			args = append(args, "-d", s)
		}
	}

	switch req.Challenge {
	case SSLChallengeCloudflareDNS:
		args = append(args, "--dns", "dns_cf")
	case SSLChallengeStandaloneDomain:
		args = append(args, "--standalone")
		args = append(args, sslListenArg(req)...)
	case SSLChallengeStandaloneIP:
		// Every one of these is load-bearing, and all three were established the
		// hard way in vpn-ui.sh:610-650:
		//   --cert-profile shortlived  the ONLY Let's Encrypt profile whose
		//                              permitted identifiers include `ip`. Without
		//                              it the order is refused outright.
		//   --standalone               an IP identifier has nothing to hang a TXT
		//                              record on, and tls-alpn-01 wants port 443.
		//   --days -2                  see sslRenewalDays: the certificate is ~160
		//                              hours, not the 90 days acme.sh assumes.
		args = append(args, "--standalone", "--cert-profile", "shortlived", "--days", sslRenewalDays)
		args = append(args, sslListenArg(req)...)
	case SSLChallengeWebroot:
		root := strings.TrimSpace(req.WebrootPath)
		if root == "" {
			return nil, errors.New("the webroot challenge needs the directory the webserver serves")
		}
		// NO --standalone and NO --listen-v4/--listen-v6, and their absence is the
		// whole feature rather than an omission: acme.sh binds nothing on this path,
		// it writes the token into <root>/.well-known/acme-challenge/ and lets
		// whatever already owns port 80 serve it (acme.sh:5570-5598). Passing a
		// listen family here would be meaningless, and passing --standalone as well
		// would append a SECOND method to Le_Webroot and start a listener that
		// cannot bind.
		args = append(args, "--webroot", root)
		// An IP identifier needs the same two flags it needs on the standalone
		// path, for reasons that have nothing to do with who serves the token:
		// shortlived is the only Let's Encrypt profile whose permitted identifiers
		// include `ip`, and a 160-hour certificate needs the negative --days or
		// acme.sh renews it on 90-day arithmetic. Webroot is the better home for an
		// IP certificate than standalone is: it renews every few days forever, and
		// standalone would mean stopping the operator's webserver every time.
		if sslAnyIPIdentifier(req.Identifiers) {
			args = append(args, "--cert-profile", "shortlived", "--days", sslRenewalDays)
		}
	default:
		return nil, fmt.Errorf("unknown challenge %q", req.Challenge)
	}

	return append(args, "--keylength", sslKeyLength(req.KeyType)), nil
}

// The key algorithm, and the values acme.sh will accept for it.
//
// acme.sh decides RSA vs EC by exclusion: _isEccKey (acme.sh:1172-1184) treats a
// length as EC unless it is one of 1024/2048/3072/4096/8192, and _createkey
// (acme.sh:1197-1207) maps the ec- spellings onto prime256v1, secp384r1 and
// secp521r1. So the accepted set is fixed and small, and anything outside it
// silently becomes an EC request for a curve openssl does not know.
const (
	// SSLKeyRSA2048 is the DEFAULT, and it stays the default for compatibility
	// rather than for cryptography. Legacy Windows is precisely the audience for
	// the SSTP and IKEv2 consumers on this box, and it is the client most likely
	// to refuse an EC certificate.
	SSLKeyRSA2048 = "2048"
	SSLKeyRSA4096 = "4096"
	SSLKeyEC256   = "ec-256"
	SSLKeyEC384   = "ec-384"
)

// sslKeyLength maps a requested key type onto the --keylength acme.sh wants,
// falling back to RSA-2048 for anything unrecognised.
//
// FALLS BACK RATHER THAN ERRORING on purpose: this runs after the preflight, with
// the CA about to be contacted, and refusing an issuance at that point over a
// spelling would waste the whole run. An unknown value can only come from a
// hand-made request, and the safest answer to one is the most compatible key.
func sslKeyLength(keyType string) string {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case SSLKeyRSA4096:
		return SSLKeyRSA4096
	case SSLKeyEC256:
		return SSLKeyEC256
	case SSLKeyEC384:
		return SSLKeyEC384
	default:
		return SSLKeyRSA2048
	}
}

// SSLKeyTypeValid reports whether a key type is one this panel offers, so a form
// can be refused BEFORE anything is metered rather than silently downgraded.
func SSLKeyTypeValid(keyType string) bool {
	k := strings.ToLower(strings.TrimSpace(keyType))
	return k == "" || k == SSLKeyRSA2048 || k == SSLKeyRSA4096 || k == SSLKeyEC256 || k == SSLKeyEC384
}

// sslRenewalDays is the --days value for a short-lived certificate, and it is
// NEGATIVE on purpose.
//
// Verified against _calc_next_renew_time in the bundled acme.sh 3.1.4:
//
//   - A POSITIVE --days N takes the branch at acme.sh:5995 and computes
//     `create + N*86400 - 86400`, i.e. renewal at creation + (N-1) days. So the
//     `--days 3` that vpn-ui.sh used to pass renews every TWO days: about 3.5
//     issuances per 7-day window against a hard cap of 5 with no override form.
//   - A NEGATIVE --days -N takes a completely different branch at acme.sh:5976 and
//     computes `expiry + (-N)*86400`, i.e. renewal N days BEFORE expiry.
//
// On a 160-hour (6.67 day) certificate, -2 puts renewal at 4.67 days of age, about
// 1.5 per week, and leaves two days of margin for a daily schedule to catch it.
// acme.sh prints a hint recommending exactly this for short-lived CAs
// (acme.sh:6037).
const sslRenewalDays = "-2"

// sslAnyIPIdentifier reports whether the set names a bare address. The preflight
// refuses a set that mixes names and addresses, so in practice this is "all of
// them"; it answers on "any" so that a caller which skipped the preflight still
// gets the profile the IP requires rather than an order the CA refuses outright.
func sslAnyIPIdentifier(ids []string) bool {
	for _, id := range ids {
		if net.ParseIP(strings.TrimSpace(id)) != nil {
			return true
		}
	}
	return false
}

func sslListenArg(req SSLIssueRequest) []string {
	if req.ListenV6 {
		return []string{"--listen-v6"}
	}
	return []string{"--listen-v4"}
}

// renewArgs builds the --renew invocation, the ARI-exempt path. The per-domain
// conf already remembers the challenge, the SAN list and the profile, so this
// deliberately re-states nothing but the server.
func (d *sslAcmeDriver) renewArgs(req SSLIssueRequest) ([]string, error) {
	primary := req.Primary()
	if primary == "" {
		return nil, errors.New("no identifier given")
	}
	return append(d.baseArgs(req), "--renew", "-d", primary), nil
}

// installArgs writes the issued material into the per-set landing zone.
// --reloadcmd is `true` because there is nothing to reload: the panel re-reads the
// pair per handshake, and the consumers that genuinely need action are handled in
// Go by the fan-out (sslconsumers.go), which knows which of them drop users.
func (d *sslAcmeDriver) installArgs(req SSLIssueRequest, certPath, keyPath string) ([]string, error) {
	primary := req.Primary()
	if primary == "" {
		return nil, errors.New("no identifier given")
	}
	return append(d.baseArgs(req),
		"--install-cert", "-d", primary,
		"--key-file", keyPath,
		"--fullchain-file", certPath,
		"--reloadcmd", "true",
	), nil
}

// sslInstallPaths is the stable landing zone for one identifier set.
func (d *sslAcmeDriver) sslInstallPaths(setKey string) (dir, certPath, keyPath string, err error) {
	dir = filepath.Join(d.storeRoot, sslInstallDir, sslSetDirName(setKey))
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", "", "", fmt.Errorf("create install dir: %w", err)
	}
	return dir, filepath.Join(dir, sslCertFileName), filepath.Join(dir, sslKeyFileName), nil
}

// exec runs acme.sh and returns its combined output.
func (d *sslAcmeDriver) exec(args []string, env []string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sslAcmeTimeout)
	defer cancel()
	return d.run(ctx, SSLAcmeScript(d.storeRoot), args, env)
}

// issuedChainPath finds where acme.sh actually put the chain.
//
// Gates on the FULLCHAIN FILE, never on the domain directory. acme.sh creates the
// directory (and a domain key inside it) even when validation fails, so its
// presence proves nothing. vpn-ui.sh:663-681 records what gating on the directory
// cost: a failed issuance marched straight into --install-cert, which then died on
// a missing fullchain.cer and left a partial key behind.
func (d *sslAcmeDriver) issuedChainPath(primary string) string {
	home := SSLAcmeHome(d.storeRoot)
	for _, dir := range []string{primary, primary + "_ecc"} {
		p := filepath.Join(home, dir, "fullchain.cer")
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			return p
		}
	}
	return ""
}
