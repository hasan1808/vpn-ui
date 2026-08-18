// Package main is the entry point for the pro-ui web panel application.
// It initializes the database, web server, and handles command-line operations for managing the panel.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/corebundle"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/sub"
	"github.com/hasan1808/pro-ui/util/crypto"
	"github.com/hasan1808/pro-ui/util/random"
	"github.com/hasan1808/pro-ui/util/sys"
	"github.com/hasan1808/pro-ui/web"
	"github.com/hasan1808/pro-ui/web/global"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/joho/godotenv"
	"github.com/op/go-logging"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// initLogger initializes the logger at the configured level. It is shared by the
// web server and by CLI subcommands (e.g. `setup`) that call into services which
// log — without it those services dereference the package's nil logger and panic.
func initLogger() {
	switch config.GetLogLevel() {
	case config.Debug:
		logger.InitLogger(logging.DEBUG)
	case config.Info:
		logger.InitLogger(logging.INFO)
	case config.Notice:
		logger.InitLogger(logging.NOTICE)
	case config.Warning:
		logger.InitLogger(logging.WARNING)
	case config.Error:
		logger.InitLogger(logging.ERROR)
	default:
		log.Fatalf("Unknown log level: %v", config.GetLogLevel())
	}
}

// runWebServer initializes and starts the web server for the pro-ui panel.
// stdoutIsTTY reports whether stdout is an interactive terminal, so ANSI colour
// is only emitted when it will render (and not when output is piped/redirected).
func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// isInfoArg reports whether an argument is a harmless info switch (version/help)
// that should run without root.
func isInfoArg(a string) bool {
	switch strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-") {
	case "v", "version", "h", "help":
		return true
	}
	return false
}

// requireRoot exits with a clear error when the binary is run without root. The
// panel binds privileged ports, writes /etc and systemd units, manages nftables
// and policy routing, and supervises the bundled VPN daemons — none of which
// work without root. Colored on a TTY (honors NO_COLOR).
func requireRoot() {
	if os.Geteuid() == 0 {
		return
	}
	const m = "vpn-ui must be run as root. It binds privileged ports, writes systemd units, and manages nftables, routing and the VPN daemons.\n       Try: sudo vpn-ui"
	if fi, err := os.Stderr.Stat(); err == nil && os.Getenv("NO_COLOR") == "" && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintf(os.Stderr, "\x1b[1;38;5;203mError:\x1b[0m %s\n", m)
	} else {
		fmt.Fprintf(os.Stderr, "Error: %s\n", m)
	}
	os.Exit(1)
}

// ansiProUI renders "[PRO-UI]" in the panel logo's colours — teal brackets,
// deep-teal letters, a green hyphen — as a bold CLI banner. Falls back to plain
// text when NO_COLOR is set or stdout isn't a TTY.
func ansiProUI() string {
	const text = "[PRO-UI]"
	if os.Getenv("NO_COLOR") != "" || !stdoutIsTTY() {
		return text
	}
	// 24-bit colour matched to media/logo.png.
	const (
		reset   = "\x1b[0m"
		bracket = "\x1b[1;38;2;23;212;212m" // bright teal  #17d4d4
		letter  = "\x1b[1;38;2;14;165;165m" // deep teal    #0ea5a5
		hyphen  = "\x1b[1;38;2;79;175;100m" // green        #4faf64
	)
	var b strings.Builder
	for _, r := range text {
		switch r {
		case '[', ']':
			b.WriteString(bracket)
		case '-':
			b.WriteString(hyphen)
		default:
			b.WriteString(letter)
		}
		b.WriteRune(r)
	}
	b.WriteString(reset)
	return b.String()
}

// warnUnsupportedDistro prints a prominent warning at panel startup when the host
// distro is not on pro-ui's tested list (service.DistroSupported). Colorful when
// stdout is a TTY (honors NO_COLOR); always also emits a logger.Warning so it lands
// in the journal / non-TTY logs too.
func warnUnsupportedDistro() {
	ok, pretty, reason := service.DistroSupported()
	if ok {
		return
	}
	logger.Warningf("unsupported distro: %s (%s) — not officially supported by pro-ui, expect errors",
		pretty, reason)

	tested := service.SupportedDistroSummary()
	if os.Getenv("NO_COLOR") != "" || !stdoutIsTTY() {
		fmt.Fprintf(os.Stderr,
			"\nWARNING: %s is NOT officially supported by pro-ui. It may run, but expect errors.\n"+
				"Tested distros: %s.\n\n", pretty, tested)
		return
	}
	const (
		reset = "\x1b[0m"
		yb    = "\x1b[1;93m" // bold yellow
		rb    = "\x1b[1;91m" // bold red
		dim   = "\x1b[2m"
	)
	rule := yb + strings.Repeat("━", 64) + reset
	fmt.Fprintln(os.Stderr, "\n"+rule)
	fmt.Fprintln(os.Stderr, rb+"⚠  UNSUPPORTED DISTRO"+reset)
	fmt.Fprintf(os.Stderr, "%s%s%s is not officially supported by pro-ui — %sexpect errors%s.\n",
		yb, pretty, reset, rb, reset)
	fmt.Fprintf(os.Stderr, "%sTested: %s%s\n", dim, tested, reset)
	fmt.Fprintln(os.Stderr, rule+"\n")
}

func runWebServer() {
	requireRoot()
	fmt.Println(ansiProUI())
	log.Printf("Starting %v %v", config.GetName(), config.GetVersion())

	initLogger()

	warnUnsupportedDistro()

	_ = godotenv.Load() // .env is optional; ignore if missing

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	// Give the VPN-protocol accounts that predate their subscription support a subId,
	// so they have a subscription link at all. This runs on every start rather than
	// only from MigrateDB, because MigrateDB is reached only by the `migrate`
	// subcommand and the DB-import path: a panel that is simply upgraded and
	// restarted never calls it, which is the normal way this fix arrives. Idempotent
	// and cheap (it writes only the inbounds that were actually missing one).
	inboundMigrations := &service.InboundService{}
	inboundMigrations.MigrationSubIds()
	// Same reason, and the same requirement to run before anything serves: stamp each
	// pool-protocol account with the slot it is already using, so its tunnel address stops
	// depending on its position in the client list. Deleting an account used to renumber
	// every later one, moving live sessions onto other accounts' addresses and breaking
	// installed WireGuard configs outright.
	inboundMigrations.MigrationAccountSlots()
	// Backfill the accounts layer from settings.clients. Ordered AFTER the two
	// above on purpose: every account must already carry its subId and its slot
	// before anything reads them onto a membership row.
	//
	// ADDITIVE ONLY (see MigrationAccounts): it inserts into accounts and
	// account_inbounds and writes nothing else, so a failure at any point leaves
	// the database exactly as it was and the panel keeps serving on the legacy
	// client model. Never blocks startup.
	accountMigrations := &service.AccountService{}
	accountMigrations.MigrationAccounts()
	// Seed the per-inbound usage breakdown from the usage that already exists, which
	// needs the memberships above to be there. Also on every start and for the same
	// reason: MigrateDB is reached only by the `migrate` subcommand and the DB-import
	// path, so a panel that is simply upgraded would never run it. One shot, guarded
	// by a setting, and never blocking startup - the breakdown is a display figure
	// and every enforcement path still reads client_traffics.
	accountMigrations.MigrationMembershipUsage()
	// Clear the records a failed delete left behind on every install that predates
	// the delete fixes: memberships of inbounds that are gone, accounts serving
	// nothing, and traffic rows no settings entry claims. Each of those holds an
	// email against a re-create, which is what operators report as the panel
	// refusing a "Duplicate email" for a customer they deleted. Ordered AFTER the
	// backfill above, so the memberships it is judging are the complete set.
	//
	// Same reason as the three above for being here and not in MigrateDB, one shot,
	// guarded by its own setting, and never blocking startup. It deletes only records
	// nothing can reach, and REPORTS rather than touches the entries that resolve to
	// one account identity, which are live customers.
	inboundMigrations.MigrationCleanupOrphans()
	// Same reason again: hand the admins who predate the overview permission the bit
	// that now gates the page they could always open, so an upgrade does not quietly
	// take the panel's home page away from every non-super admin. One shot, guarded by
	// a setting so a later revoke stays revoked (see MigrationOverviewAccess).
	adminMigrations := &service.AdminService{}
	adminMigrations.MigrationOverviewAccess()

	// Ensure any prebuilt bundles present in the project's releases are fetched
	// when the embedded assets are not present. This helps fresh checkouts and CI
	// deployments that did not run the full build backend step to produce embedded
	// binaries.
	backend.DownloadBundlesIfMissing()

	// Give every Xray-native wireguard inbound its device keypair, its clients array
	// and one tunnel address per client device. Idempotent and cheap (it touches
	// nothing that is already right), so it runs on every start rather than behind a
	// flag: an inbound created before this release has no clients array at all, and
	// until it has one the Clients page cannot offer it as somewhere to put an
	// account. See web/service/wgxray.go.
	service.ReconcileAllWireguardXrayKeys()

	// Take over the certificate deploy.sh or the vpn-ui.sh menu installed, so the
	// panel manages and renews it instead of leaving it to acme.sh's own cron.
	//
	// HERE, AND NOT IN web.go, for one reason that decides it: the TLS reloader is
	// built once from webCertFile when the server starts, and watches THAT path for
	// the life of the process (network/cert_reloader.go:69-83). Adopting after the
	// listener exists rewrites the setting without moving the listener, so the panel
	// would keep serving the legacy path while the panel's own renewals went into
	// the store copy, and the two would drift apart until the next restart. Running
	// before server.Start() means this boot already serves the managed path.
	//
	// Idempotent, so it is safe on every start: adoption skips any certificate whose
	// issuer and serial a profile already holds.
	var sslSync service.SSLService
	sslSync.SyncLegacyCertificates()

	// Extract the pinned Xray core + base geo files baked into the panel. The
	// core is overwritten on every start so the bundled (patched) fork is always
	// what runs — switching/updating it from the dashboard is disabled. Geo files
	// are written only when missing, so dashboard geo updates persist. On a build
	// without an embedded bundle (checkout without build/core/build.sh output),
	// both calls are no-ops and the panel uses whatever is already on disk.
	binDir := config.GetBinFolderPath()
	if p, exErr := corebundle.ExtractXray(binDir); exErr != nil {
		logger.Warning("could not extract bundled xray core:", exErr)
	} else if p != "" {
		logger.Info("extracted bundled xray core to", p)
	}
	if geo, exErr := corebundle.ExtractGeofiles(binDir); exErr != nil {
		logger.Warning("could not extract bundled geo files:", exErr)
	} else if len(geo) > 0 {
		logger.Info("extracted bundled geo files:", geo)
	}

	// Same deal for the bundled VPN daemons, and for the same reason: what runs must
	// be what this binary ships. They used to be extracted ONLY by the panel's
	// one-time provisioning (runProvisionSteps, gated by vpnProvisioned), so an
	// already-provisioned host kept its original daemons forever and a panel upgrade
	// could never deliver a daemon fix. The symptom is brutal to diagnose, because
	// the panel is new and writes correct config while an OLD daemon reads it and
	// silently ignores whatever it does not understand (telemt drops unknown keys,
	// so per-account modes just stopped being enforced). Fresh installs never see
	// it, which is exactly why the E2E cannot catch it: a new VM has no bin/ yet.
	//
	// Extract before the web server starts the daemons, so they exec the new files.
	// A daemon somehow still running keeps its old inode (writeExecutable renames
	// rather than overwrites, to dodge ETXTBSY) and picks the new one up on its next
	// restart.
	//
	// Scoped to the cores this host actually installed: setup is per-core now, and
	// "installed" is decided by the binary being present on disk, so refreshing the
	// WHOLE bundle here would silently re-install every core on the next restart
	// and undo any uninstall. See service.RefreshInstalledDaemons for the
	// pre-per-core-tracking case, which still gets the full bundle.
	if backend.Available() {
		if files, exErr := service.RefreshInstalledDaemons(); exErr != nil {
			logger.Warning("could not extract bundled VPN daemons:", exErr)
		} else if len(files) > 0 {
			logger.Info("extracted bundled VPN daemons:", len(files), "files to", backend.BinDir())
		}
	}

	// Ensure the `vpn-ui` management menu is installed, so the command works on a
	// hand-deployed box that never ran deploy.sh's `install-menu`. Idempotent and
	// best-effort; see ensureMenuInstalled.
	ensureMenuInstalled()

	// The root-only control socket the `vpn-ui-amd64 ctl` CLI (and the vpn-ui menu)
	// drives Xray and the daemons through. Started before the servers, so it is
	// already answering by the time the panel is up, and NON-FATAL on failure: it is
	// a convenience for the CLI, and a panel carrying VPN traffic without it beats a
	// panel that refused to boot over it.
	if err := service.StartControlSocket(); err != nil {
		logger.Warning("control socket unavailable (the vpn-ui menu's Xray/cores items will not work):", err)
	}

	var server *web.Server
	server = web.NewServer()
	global.SetWebServer(server)
	err = server.Start()
	if err != nil {
		log.Fatalf("Error starting web server: %v", err)
	}

	var subServer *sub.Server
	subServer = sub.NewServer()
	subServer.SetEmbedded(web.EmbeddedHTML(), web.EmbeddedAssets())
	global.SetSubServer(subServer)
	err = subServer.Start()
	if err != nil {
		log.Fatalf("Error starting sub server: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	// Trap shutdown signals
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, sys.SIGUSR1)
	for {
		sig := <-sigCh

		switch sig {
		case syscall.SIGHUP:
			logger.Info("Received SIGHUP signal. Restarting servers...")

			// --- FIX FOR TELEGRAM BOT CONFLICT (409): Stop bot before restart ---
			service.StopBot()
			// --

			err := server.Stop()
			if err != nil {
				logger.Debug("Error stopping web server:", err)
			}
			err = subServer.Stop()
			if err != nil {
				logger.Debug("Error stopping sub server:", err)
			}

			server = web.NewServer()
			global.SetWebServer(server)
			err = server.Start()
			if err != nil {
				log.Fatalf("Error restarting web server: %v", err)
			}
			log.Println("Web server restarted successfully.")

			subServer = sub.NewServer()
			subServer.SetEmbedded(web.EmbeddedHTML(), web.EmbeddedAssets())
			global.SetSubServer(subServer)
			err = subServer.Start()
			if err != nil {
				log.Fatalf("Error restarting sub server: %v", err)
			}
			log.Println("Sub server restarted successfully.")
		case sys.SIGUSR1:
			logger.Info("Received USR1 signal, restarting xray-core...")
			err := server.RestartXray()
			if err != nil {
				logger.Error("Failed to restart xray-core:", err)
			}

		default:
			// --- FIX FOR TELEGRAM BOT CONFLICT (409) on full shutdown ---
			service.StopBot()
			// ------------------------------------------------------------

			if err := server.Stop(); err != nil {
				logger.Warning("Error stopping server:", err)
			}
			if err := subServer.Stop(); err != nil {
				logger.Warning("Error stopping sub server:", err)
			}
			log.Println("Shutting down servers.")
			return
		}
	}
}

// installSystemd creates the panel's systemd unit, enables it at boot, and starts
// it — so the panel runs under systemd instead of a direct binary execution.
// Invoked by `vpn-ui --systemd`. Must run as root (it writes /etc/systemd/system).
func installSystemd() {
	if err := database.InitDB(config.GetDBPath()); err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}
	var s service.SystemdService
	name := s.GetServiceName()
	fmt.Printf("Installing systemd service %q (create + enable on boot + start now)...\n", name)
	err := s.SaveService(service.SaveServiceRequest{
		Name:   name,
		Unit:   service.DefaultUnit(name),
		Enable: true,
		Start:  true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "systemd install failed:", err)
		os.Exit(1)
	}
	fmt.Printf("Done. The panel now runs under systemd as %q.\n", name)
	fmt.Printf("  status: systemctl status %s\n", name)
	fmt.Printf("  logs:   journalctl -u %s -f\n", name)
}

// runUninstall removes the panel and everything it installed on the host: the
// systemd unit, child daemons, firewall/nftables rules, policy routing, the
// /etc configs, the bundled daemon trees, logs, the database and finally the
// binary itself. It is the inverse of `--systemd`/provisioning. Distro packages
// (libreswan, nftables, iproute2, kernel modules) and irreversible boot/modprobe
// edits are left in place and flagged for the operator. Invoked by
// `vpn-ui --uninstall`; `--yes`/`--force` skips the confirmation prompt. Must run
// as root. Best-effort: a single failed step is recorded, not fatal.
//
// coresAnswer pre-answers "remove the installed VPN cores too?": service.InboundsKeep
// ("keep") or service.InboundsDelete ("delete"), empty when unset. Unset asks,
// except under assumeYes.
func runUninstall(assumeYes bool, coresAnswer string) {
	// The teardown calls services that log through the logger package (unlike
	// SaveService), so initialise it first to avoid a nil-logger panic.
	initLogger()
	// The DB is only needed to read the configured systemd service name and the
	// installed-core list; if it's already gone we still tear down the rest of the
	// host with defaults.
	dbOK := true
	if err := database.InitDB(config.GetDBPath()); err != nil {
		dbOK = false
		fmt.Fprintln(os.Stderr, "warning: database unavailable, using defaults:", err)
	}

	exePath, _ := os.Executable()

	// The cores actually installed here, so the question below can name what is at
	// stake. Only when the DB opened: CoreCatalog reads the settings table and the
	// per-core inbound counts, and a nil *gorm.DB nil-derefs rather than erroring.
	var installedCores []string
	if dbOK {
		var cs service.CoreService // zero-value usable and stateless
		for _, c := range cs.CoreCatalog() {
			if !c.Builtin && c.Installed {
				installedCores = append(installedCores, c.Title)
			}
		}
	}

	// One reader for BOTH questions. A second bufio.NewReader(os.Stdin) would
	// start with an empty buffer while the first one has already swallowed the
	// next line: on a tty that is invisible, but piped input (`printf 'yes\nn\n'`)
	// loses the second answer and blocks on EOF.
	stdin := bufio.NewReader(os.Stdin)

	// Whether the cores get their own question: only when nothing pre-answered it,
	// the run is interactive, and there is something to keep. A DB that would not
	// open still asks, since "no cores installed" is then unproven.
	askCores := coresAnswer == "" && !assumeYes && (!dbOK || len(installedCores) > 0)

	if !assumeYes {
		fmt.Println("This will REMOVE pro-ui and everything it installed on this host:")
		fmt.Println("  • the systemd unit, child daemons (openvpn/xl2tpd/pptpd/pluto)")
		fmt.Println("  • nftables 'ip vpn' table, firewalld trust, fwmark routing (table 100)")
		fmt.Println("  • /etc configs, /usr/libexec/vpn-ui bundles, logs, bin/, the database")
		fmt.Println("  • the pro-ui binary itself")
		fmt.Println("Distro packages and boot/modprobe edits are kept and listed at the end.")
		if askCores {
			// The list above is the FULL teardown, which is not what happens if the
			// next question is answered "keep". Say so here rather than let the
			// operator agree to a removal that then silently does not occur.
			fmt.Println("Whether the installed VPN cores go too is a separate question, asked next.")
		}
		fmt.Print("Type 'yes' to proceed: ")
		line, _ := stdin.ReadString('\n')
		if strings.TrimSpace(line) != "yes" {
			fmt.Println("Aborted — nothing was removed.")
			return
		}
	}

// Keep or remove the cores. The two defaults are deliberately OPPOSITE:
	//
	//   --yes  removes them, because that is what `--uninstall --yes` has always
	//          done and what every unattended caller (deploy scripts, the E2E
	//          harness) asserts on. Changing it would silently break automation.
	//   a bare Enter keeps them, because typing "yes" to "remove pro-ui" is not
	//          the same as agreeing to take a live VPN service down with it, and
	//          the cores are the expensive half to rebuild.
	keepCores := false
	switch {
	case coresAnswer == service.InboundsKeep:
		keepCores = true
	case askCores:
		keepCores = askKeepCores(stdin, installedCores)
	default:
		// service.InboundsDelete, --yes, or an interactive run with no core
		// installed: nothing to spare, so the teardown stays whole.
	}

	fmt.Println("Uninstalling pro-ui...")
	report := service.Uninstall(service.UninstallOptions{ExePath: exePath, KeepCores: keepCores})
	if keepCores && len(installedCores) > 0 {
		report.Kept = append(report.Kept, "cores left installed: "+strings.Join(installedCores, ", "))
	}

	// Remove the database (next to the binary) — done here, after the service
	// teardown that needed it to resolve the unit name.
	dbPath := config.GetDBPath()
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal"} {
		if err := os.Remove(p); err == nil {
			report.Removed = append(report.Removed, p)
		} else if !os.IsNotExist(err) {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", p, err))
		}
	}

	// Remove the running binary last. On Linux unlinking a running executable is
	// safe — the inode lives until this process exits.
	if exePath != "" {
		if err := os.Remove(exePath); err == nil {
			report.Removed = append(report.Removed, exePath)
		} else if !os.IsNotExist(err) {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", exePath, err))
		}
		// Then the install directory, but ONLY when the teardown emptied it.
		// os.Remove on a directory is a plain rmdir: it refuses a non-empty one,
		// which is exactly the guard wanted here — an operator who kept notes or
		// their own files in /opt/vpn-ui does not lose them, while the usual case
		// (nothing left but the directory itself) stops leaving a stale dir on
		// every uninstalled host.
		if dir := filepath.Dir(exePath); dir != "" && dir != "/" && dir != "." {
			if err := os.Remove(dir); err == nil {
				report.Removed = append(report.Removed, dir)
			}
		}
	}

	fmt.Printf("\nRemoved %d item(s).\n", len(report.Removed))
	for _, r := range report.Removed {
		fmt.Println("  -", r)
	}
	if len(report.Kept) > 0 {
		fmt.Println("\nKept in place — remove manually if you no longer want them:")
		for _, k := range report.Kept {
			fmt.Println("  -", k)
		}
	}
	if len(report.Errors) > 0 {
		fmt.Println("\nEncountered errors (best-effort, teardown continued):")
		for _, e := range report.Errors {
			fmt.Println("  !", e)
		}
	}
	fmt.Println("\npro-ui uninstalled.")
}

// askKeepCores asks whether the installed VPN cores should come off the host as
// well, and returns true to KEEP them. Anything other than an explicit yes keeps
// them, EOF included: see runUninstall for why the interactive default is the
// opposite of --yes's.
//
// The RADIUS sentence is not padding. Six of the ten installable cores
// authenticate against a RADIUS server that runs in-process inside this binary
// on 127.0.0.1:1812/1813, so "keep the cores" keeps their files and their
// listening sockets but not their ability to let anybody new in. An operator who
// learns that afterwards files it as a bug.
func askKeepCores(stdin *bufio.Reader, installed []string) bool {
	fmt.Println()
	fmt.Println("Remove the installed VPN cores as well?")
	if len(installed) > 0 {
		fmt.Println("  Installed: " + strings.Join(installed, ", "))
	}
	fmt.Println("  • remove: their daemons, /etc configs, bundled trees and bin/ go too,")
	fmt.Println("    along with the nftables table and fwmark routing they all pass through")
	fmt.Println("  • keep:   all of that is left exactly as it is")
	fmt.Println("RADIUS runs INSIDE the vpn-ui binary, not as a separate daemon, so kept L2TP,")
	fmt.Println("PPTP, OpenVPN, OpenConnect, SSTP and IKEv2 cores cannot authenticate new logins")
	fmt.Println("once vpn-ui is gone. WireGuard, AmneziaWG, GRE and MTProto are unaffected.")
	fmt.Print("Remove the cores too? [y/N]: ")
	line, _ := stdin.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return false
	}
	return true
}

// randomFreePort returns a random, currently-bindable TCP port in a high range,
// falling back to an OS-assigned port if the random picks keep colliding.
func randomFreePort() int {
	for i := 0; i < 20; i++ {
		p := 10000 + random.Num(55535) // 10000..65534
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err == nil {
			_ = ln.Close()
			return p
		}
	}
	if ln, err := net.Listen("tcp", ":0"); err == nil {
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	}
	return 20000 + random.Num(40000)
}

// randomizeSetting generates a fresh random port, login username, login password
// and web base path for the panel, persists them, and prints them so the operator
// can log in. Invoked by `vpn-ui --random` (composable with --systemd, which is
// applied afterwards so the unit boots with these settings).
func randomizeSetting() error {
	// Open the DB FIRST. GetServiceName below and every SettingService/UserService
	// write in this function are gorm-backed, and on a fresh install nothing has opened
	// the DB yet — calling any of them before InitDB nil-derefs gorm (SIGSEGV). This
	// ordering regressed when the stop-the-running-panel logic was added above the
	// original InitDB call; restore InitDB-first.
	if err := database.InitDB(config.GetDBPath()); err != nil {
		fmt.Println("Database initialization failed:", err)
		return err
	}

	// A running panel holds the SQLite DB open and serves the OLD port/creds/webpath.
	// Writing new settings underneath it races the live process (and the panel would
	// keep the stale values until a restart anyway), so stop the systemd-managed
	// panel first and bring it back up on the new settings afterwards. No-op on a
	// fresh install (nothing running yet); a following --systemd starts it either way.
	svc := service.SystemdService{}
	unit := svc.GetServiceName()
	panelWasActive := exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
	if panelWasActive {
		fmt.Printf("Stopping %s before applying randomized settings...\n", unit)
		_ = exec.Command("systemctl", "stop", unit).Run()
	}

	settingService := service.SettingService{}
	userService := service.UserService{}

	port := randomFreePort()
	username := random.Seq(12)
	password := random.Seq(20)
	webBasePath := random.Seq(16)

	if err := settingService.SetPort(port); err != nil {
		fmt.Println("Failed to set port:", err)
		return err
	}
	if err := userService.UpdateFirstUser(username, password); err != nil {
		fmt.Println("Failed to set username and password:", err)
		return err
	}
	if err := settingService.SetBasePath(webBasePath); err != nil {
		fmt.Println("Failed to set web base path:", err)
		return err
	}

	// Read the base path back so the printed value matches how it is stored
	// (SetBasePath normalizes leading/trailing slashes).
	normPath, _ := settingService.GetBasePath()
	if normPath == "" {
		normPath = "/"
	}
	ip, url := panelAccessURL(&settingService, port, normPath)

	fmt.Println(ansiProUI())
	fmt.Println("Randomized panel settings:")
	fmt.Printf("  Port:     %d\n", port)
	fmt.Printf("  Username: %s\n", username)
	fmt.Printf("  Password: %s\n", password)
	fmt.Printf("  WebPath:  %s\n", normPath)
	fmt.Printf("  IP:       %s\n", ip)
	fmt.Printf("  URL:      %s\n", url)
	if ip == "N/A" {
		fmt.Println("  (could not detect public IP, substitute the server's address in the URL)")
	}

	// Bring the panel back up on the new settings (only if we stopped it above; on a
	// fresh install a following --systemd starts it instead).
	if panelWasActive {
		fmt.Printf("Restarting %s with the new settings...\n", unit)
		_ = exec.Command("systemctl", "start", unit).Run()
	}
	return nil
}

// applyExplicitSetting sets the panel login username/password, web port and/or web
// base path to explicit values from `vpn-ui --user/--pass/--port/--path`. It uses
// the exact same "work safe" envelope as randomizeSetting: open the DB first, stop
// the running systemd panel (it holds the DB open and serves the old values), write
// the changes, then bring it back up so the live panel serves the new values. Any
// subset of the four may be given; omitted values are left unchanged. Composable
// with --systemd, which runs afterwards.
func applyExplicitSetting(username, password string, port int, webBasePath string) error {
	// InitDB FIRST — every service call below is gorm-backed (see randomizeSetting's
	// note on the SIGSEGV this ordering avoids).
	if err := database.InitDB(config.GetDBPath()); err != nil {
		fmt.Println("Database initialization failed:", err)
		return err
	}

	svc := service.SystemdService{}
	unit := svc.GetServiceName()
	panelWasActive := exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
	if panelWasActive {
		fmt.Printf("Stopping %s before applying settings...\n", unit)
		_ = exec.Command("systemctl", "stop", unit).Run()
	}

	settingService := service.SettingService{}
	userService := service.UserService{}

	if port > 0 {
		if port < 1 || port > 65535 {
			fmt.Println("Ignoring invalid port (must be 1-65535):", port)
		} else if err := settingService.SetPort(port); err != nil {
			fmt.Println("Failed to set port:", err)
		}
	}
	if username != "" || password != "" {
		if err := applyCredential(&userService, username, password); err != nil {
			fmt.Println("Failed to set username/password:", err)
		}
	}
	if webBasePath != "" {
		if err := settingService.SetBasePath(webBasePath); err != nil {
			fmt.Println("Failed to set web base path:", err)
		}
	}

	// Print the resulting login/access config (same shape as --random, minus the
	// password, which the operator supplied). Values are read back so the printout
	// reflects what is actually stored, including any left unchanged.
	normPath, _ := settingService.GetBasePath()
	if normPath == "" {
		normPath = "/"
	}
	curPort, _ := settingService.GetPort()
	curUser := ""
	if u, err := userService.GetFirstUser(); err == nil && u != nil {
		curUser = u.Username
	}
	ip, url := panelAccessURL(&settingService, curPort, normPath)
	fmt.Println("Applied panel settings:")
	fmt.Printf("  Port:     %d\n", curPort)
	fmt.Printf("  Username: %s\n", curUser)
	fmt.Printf("  WebPath:  %s\n", normPath)
	fmt.Printf("  IP:       %s\n", ip)
	fmt.Printf("  URL:      %s\n", url)
	if ip == "N/A" {
		fmt.Println("  (could not detect public IP, substitute the server's address in the URL)")
	}

	if panelWasActive {
		fmt.Printf("Restarting %s with the new settings...\n", unit)
		_ = exec.Command("systemctl", "start", unit).Run()
	}
	return nil
}

// panelAccessURL resolves the server's public IPv4 the same way the dashboard does
// and assembles the one-click panel URL from it. The scheme follows the TLS
// setting: a configured web cert (e.g. deploy.sh's self-signed / Let's Encrypt
// options) means the panel serves HTTPS, so the printed link must match or it
// won't connect. Shared by --random, --user/--pass/--port/--path and `info` so the
// three can never print different links for the same panel.
//
// The public-IP lookup is an HTTP call to an external service, so callers that do
// not display the URL should not call this at all (see collectPanelInfo).
func panelAccessURL(settingService *service.SettingService, port int, normPath string) (ip, url string) {
	ip = service.GetServerIPv4()
	scheme := "http"
	host := ip
	if certFile, _ := settingService.GetCertFile(); certFile != "" {
		scheme = "https"
		// The panel serves a cert whose name is the DOMAIN (Let's Encrypt) or the
		// server IP (self-signed). A browser sent to https://<IP> when the cert names
		// only a domain fails the name check and the panel "does not load", so the
		// printed link must use the cert's own host. Fall back to the detected IP when
		// the cert has no usable name (unparsable, or CN-only with no SAN).
		if h := certHost(certFile); h != "" {
			host = h
		}
	}
	// JoinHostPort, not "%s:%d": an IPv6 host has to be bracketed or the URL is
	// malformed (https://2001:db8::1:2083/ names no port a browser can find). A
	// certificate naming a bare IPv6 address reaches here through certHost.
	return ip, fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)), normPath)
}

// certHost returns the host a browser should use to reach a panel serving certFile:
// the leaf certificate's first routable DNS SAN, else its first non-loopback IP SAN,
// else "" when the file cannot be read or parsed. "localhost" and loopback IPs are
// skipped, so a self-signed panel cert (which also carries them for local access)
// still yields the server's public address. It reads the FIRST certificate in the
// PEM (the leaf; a fullchain.pem puts intermediates after it) and does not fall back
// to the deprecated CN, which browsers no longer match on.
func certHost(certFile string) string {
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return ""
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return ""
		}
		// Prefer a host a REMOTE browser can actually reach. The self-signed panel
		// cert (deploy.sh's HTTPS option) carries "localhost" + 127.0.0.1 loopback
		// SANs, so it validates for local access too, alongside the server's public
		// IP. Returning the first SAN blindly hands back "localhost", so --random
		// prints https://localhost:PORT, which no remote browser can open. Skip the
		// loopback/localhost identities and return the first routable SAN.
		for _, name := range cert.DNSNames {
			if !strings.EqualFold(name, "localhost") {
				return name
			}
		}
		for _, ip := range cert.IPAddresses {
			if !ip.IsLoopback() {
				return ip.String()
			}
		}
		return ""
	}
}

// panelInfo is the panel's login/access + service state, as printed by
// `vpn-ui info`. The JSON field names are a CONTRACT with the vpn-ui menu script:
// they are what `--json` emits and what `--get <field>` looks up, so the script
// never greps human output. That coupling (upstream's
// `x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}'`) breaks the
// moment a printed line is reworded. Keep these names stable; add, don't rename.
type panelInfo struct {
	Version              string `json:"version"`
	Username             string `json:"username"`
	Port                 int    `json:"port"`
	WebBasePath          string `json:"webBasePath"`
	ListenIP             string `json:"listenIP"`
	SSL                  bool   `json:"ssl"`
	CertFile             string `json:"certFile"`
	KeyFile              string `json:"keyFile"`
	HasDefaultCredential bool   `json:"hasDefaultCredential"`
	IP                   string `json:"ip"`
	URL                  string `json:"url"`

	SystemdAvailable bool   `json:"systemdAvailable"`
	SystemdUnit      string `json:"systemdUnit"`
	SystemdInstalled bool   `json:"systemdInstalled"`
	SystemdEnabled   bool   `json:"systemdEnabled"`
	SystemdActive    bool   `json:"systemdActive"`
	SystemdState     string `json:"systemdState"` // no-systemd | not-installed | active | inactive

	// PanelRunning is the only trustworthy answer to "is the panel up?": it is true
	// when a live panel answers on the control socket. The systemd fields above
	// cannot answer it, because the panel may be running OUTSIDE systemd (the
	// production box starts it by hand via setsid, unit inactive-but-enabled), in
	// which case SystemdActive is false while the panel serves happily.
	PanelRunning bool   `json:"panelRunning"`
	SocketPath   string `json:"socketPath"`
	ExePath      string `json:"exePath"`

	// XrayAccessLog is the file the panel's own Xray Logs page reads
	// (xray.GetAccessLogPath: the `log.access` path out of the Xray config), so the
	// menu tails exactly what the dashboard shows. Empty means Xray's access log is
	// disabled: the shipped default is literally "none", which the panel's log page
	// renders as nothing at all. XrayAccessLogArchive is the rotated copy the IP-limit
	// job keeps (3xipl-ap.log); it only has content when the access log was enabled.
	XrayAccessLog        string `json:"xrayAccessLog"`
	XrayAccessLogArchive string `json:"xrayAccessLogArchive"`
}

// collectPanelInfo reads the panel's current settings and service state. The DB
// must already be open (see runInfo).
//
// resolvePublicIP gates the IP/URL lookup because it is an HTTP round-trip to an
// external service with a 3s timeout PER provider: on a box with no outbound
// internet the menu would stall for many seconds on every single field it reads.
// Callers that only want, say, systemdUnit pass false.
func collectPanelInfo(resolvePublicIP bool) panelInfo {
	settingService := service.SettingService{}
	userService := service.UserService{}

	info := panelInfo{Version: config.GetVersion()}

	info.Port, _ = settingService.GetPort()
	info.WebBasePath, _ = settingService.GetBasePath()
	if info.WebBasePath == "" {
		info.WebBasePath = "/"
	}
	info.ListenIP, _ = settingService.GetListen()
	info.CertFile, _ = settingService.GetCertFile()
	info.KeyFile, _ = settingService.GetKeyFile()
	// The web server serves HTTPS only with BOTH files set, so report SSL the same
	// way it decides, not on the cert alone.
	info.SSL = info.CertFile != "" && info.KeyFile != ""

	if u, err := userService.GetFirstUser(); err == nil && u != nil {
		info.Username = u.Username
		info.HasDefaultCredential = u.Username == "admin" && crypto.CheckPasswordHash(u.Password, "admin")
	}

	if resolvePublicIP {
		info.IP, info.URL = panelAccessURL(&settingService, info.Port, info.WebBasePath)
	}

	// Never hardcode "vpn-ui": the unit name is operator-configurable (settings key
	// systemdServiceName), and ServiceState resolves it the same way the panel's own
	// Settings page does.
	sd := service.SystemdService{}
	st := sd.ServiceState()
	info.SystemdAvailable = st.Available
	info.SystemdUnit = st.Name
	info.SystemdInstalled = st.Installed
	info.SystemdEnabled = st.Enabled
	info.SystemdActive = st.Active
	switch {
	case !st.Available:
		info.SystemdState = "no-systemd"
	case !st.Installed:
		info.SystemdState = "not-installed"
	case st.Active:
		info.SystemdState = "active"
	default:
		info.SystemdState = "inactive"
	}

	info.SocketPath = service.ControlSocketPath()
	info.PanelRunning = ctlPing()
	info.ExePath, _ = os.Executable()

	if p, err := xray.GetAccessLogPath(); err == nil {
		// "none" is Xray's own way of spelling "disabled" and is the shipped default
		// (web/service/config.json). Normalize it to empty so the one rule a consumer
		// needs is "empty means no access log", rather than knowing Xray's sentinel.
		if p != "none" {
			info.XrayAccessLog = p
		}
	}
	info.XrayAccessLogArchive = xray.GetAccessPersistentLogPath()

	return info
}

// runInfo implements `vpn-ui info [--json|--get <field>]`: the panel's login,
// access URL and service state in one place. Menu item "View current login info"
// is just this.
//
// It opens the DB ITSELF. Every reader below (SettingService, UserService,
// SystemdService.GetServiceName) is gorm-backed, and calling one before InitDB
// nil-derefs gorm and SIGSEGVs. The legacy `setting -show` path only survives
// because updateSetting happens to run InitDB first in the same invocation.
func runInfo(args []string) error {
	// Services here log through the logger package (xray.GetAccessLogPath warns when
	// the Xray config is unreadable), which panics on a nil logger.
	initLogger()
	if err := database.InitDB(config.GetDBPath()); err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}

	asJSON, field := false, ""
	for i := 0; i < len(args); i++ {
		key := strings.TrimPrefix(strings.TrimPrefix(args[i], "-"), "-")
		if eq := strings.IndexByte(key, '='); eq >= 0 {
			if key[:eq] == "get" {
				field = key[eq+1:]
				continue
			}
		}
		switch key {
		case "json":
			asJSON = true
		case "get":
			if i+1 < len(args) {
				i++
				field = args[i]
			}
		default:
			return fmt.Errorf("unknown argument for info: %q (use --json or --get <field>)", args[i])
		}
	}

	if field != "" {
		return emitInfoField(field)
	}
	info := collectPanelInfo(true)
	if asJSON {
		out, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("encoding info failed: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}
	printPanelInfo(info)
	return nil
}

// emitInfoField prints ONE field's raw value, so a shell can branch on it without
// jq and without ever parsing prose. The lookup goes through the marshalled JSON
// rather than a hand-written switch, which is what guarantees `--get` accepts
// exactly the keys `--json` emits, forever.
func emitInfoField(field string) error {
	// Only the two fields that need it pay for the public-IP lookup.
	info := collectPanelInfo(field == "ip" || field == "url")
	raw, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("encoding info failed: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber() // keep Port an integer instead of float64's "8443" -> "8443.000000"
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("decoding info failed: %w", err)
	}
	v, ok := m[field]
	if !ok {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return fmt.Errorf("unknown info field %q\nknown fields: %s", field, strings.Join(keys, ", "))
	}
	fmt.Println(v)
	return nil
}

// printPanelInfo renders the human view, in the same shape as --random's printout.
func printPanelInfo(info panelInfo) {
	fmt.Println(ansiProUI())
	fmt.Println("Panel:")
	fmt.Printf("  Version:  %s\n", info.Version)
	fmt.Printf("  Username: %s\n", info.Username)
	fmt.Printf("  Port:     %d\n", info.Port)
	fmt.Printf("  WebPath:  %s\n", info.WebBasePath)
	listen := info.ListenIP
	if listen == "" {
		listen = "(all interfaces)"
	}
	fmt.Printf("  Listen:   %s\n", listen)
	if info.SSL {
		fmt.Printf("  SSL:      on\n")
		fmt.Printf("  Cert:     %s\n", info.CertFile)
		fmt.Printf("  Key:      %s\n", info.KeyFile)
	} else {
		fmt.Printf("  SSL:      off (the panel is served over plain HTTP)\n")
	}
	fmt.Printf("  IP:       %s\n", info.IP)
	fmt.Printf("  URL:      %s\n", info.URL)
	if info.IP == "N/A" {
		fmt.Println("  (could not detect public IP, substitute the server's address in the URL)")
	}
	if info.HasDefaultCredential {
		fmt.Println("  WARNING:  the default admin/admin credential is still in use. Change it.")
	}

	fmt.Println("Service:")
	fmt.Printf("  Unit:     %s (%s)\n", info.SystemdUnit, info.SystemdState)
	if info.SystemdAvailable && info.SystemdInstalled {
		fmt.Printf("  OnBoot:   %v\n", info.SystemdEnabled)
	}
	if info.PanelRunning {
		fmt.Printf("  Panel:    running (its control socket answers)\n")
	} else {
		fmt.Printf("  Panel:    not running (no answer on %s)\n", info.SocketPath)
	}
	// The live box runs the panel by hand under setsid with the unit inactive: say so
	// plainly, because every systemctl-based conclusion an operator would draw from
	// the line above is wrong in that state.
	if info.PanelRunning && !info.SystemdActive {
		fmt.Println("  NOTE:     the panel is running OUTSIDE systemd, so 'systemctl stop' would")
		fmt.Printf("            report success and stop nothing. Stop it by PID instead.\n")
	}
}

// ctlDial connects to the LIVE panel's control socket.
func ctlDial() (net.Conn, error) {
	return net.DialTimeout("unix", service.ControlSocketPath(), 3*time.Second)
}

// ctlSend sends one command over conn and returns the panel's reply.
func ctlSend(conn net.Conn, cmd string) (service.ControlResponse, error) {
	var resp service.ControlResponse
	req, err := json.Marshal(service.ControlRequest{Cmd: cmd})
	if err != nil {
		return resp, err
	}
	if _, err := conn.Write(append(req, '\n')); err != nil {
		return resp, err
	}
	// No read deadline: cores.restart-all restarts every core and legitimately takes
	// tens of seconds. The panel closes the connection if it dies, which unblocks us.
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return resp, err
	}
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return resp, fmt.Errorf("malformed reply from the panel: %v", jerr)
	}
	return resp, nil
}

// ctlPing reports whether a LIVE panel answers on the control socket. This is what
// lets `info` (and the menu) tell "the panel is up" from "the unit is active":
// two different things on a box where the panel was started by hand.
func ctlPing() bool {
	conn, err := ctlDial()
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	resp, err := ctlSend(conn, "ping")
	return err == nil && resp.OK
}

// runCtl implements `vpn-ui ctl <cmd> [--json]`: hand one command to the RUNNING
// panel over its control socket and print the reply.
//
// When the socket is absent or refuses, this reports that the panel is not running
// and exits non-zero. It NEVER falls back to doing the work locally, and that is
// the entire point: Xray and the daemons are children of the live panel tracked by
// its in-process state, so a local fallback would report a running Xray as stopped
// and "restart" it into a second, port-colliding copy (see web/service/control.go).
func runCtl(args []string) error {
	asJSON := false
	var cmd string
	for _, a := range args {
		if strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-") == "json" {
			asJSON = true
			continue
		}
		if cmd == "" {
			cmd = a
			continue
		}
		return fmt.Errorf("unexpected argument: %q", a)
	}
	if cmd == "" {
		return fmt.Errorf("usage: vpn-ui ctl <command> [--json]\ncommands: %s",
			strings.Join(service.ControlCommands, ", "))
	}

	conn, err := ctlDial()
	if err != nil {
		return fmt.Errorf("the vpn-ui panel is not running: no answer on %s (%v)\n"+
			"Xray and the VPN daemons are children of the running panel, so they can only\n"+
			"be controlled through it. Start the panel first, then retry.",
			service.ControlSocketPath(), err)
	}
	defer conn.Close()

	resp, err := ctlSend(conn, cmd)
	if err != nil {
		return fmt.Errorf("control socket error: %w", err)
	}
	if asJSON {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
	} else if !resp.OK {
		fmt.Fprintln(os.Stderr, "error:", resp.Error)
	} else {
		if resp.Msg != "" {
			fmt.Println(resp.Msg)
		}
		printCoreStatus(resp.Cores)
	}
	if !resp.OK {
		return fmt.Errorf("ctl command failed: %s", resp.Error)
	}
	return nil
}

// printCoreStatus renders `ctl cores.status` as an aligned table.
func printCoreStatus(cores []service.CoreStatus) {
	for _, c := range cores {
		detail := c.Detail
		if detail == "" && c.Inbounds > 0 {
			detail = fmt.Sprintf("%d inbound(s)", c.Inbounds)
		}
		if c.Version != "" {
			detail = strings.TrimSpace(c.Version + " " + detail)
		}
		fmt.Printf("  %-12s %-14s %s\n", c.Name, c.State, detail)
	}
}

// runUpdate implements `vpn-ui update`: install the latest published release over
// this binary.
//
// It deliberately does NOT call ServerService.UpdatePanel(). That path ends in
// restartPanel, which without an active systemd unit does
// syscall.Exec(exe, os.Args). That is correct for the panel process, but from the CLI it
// would re-exec the CLI with its own `update` arguments and loop. So this reuses
// the pieces (DownloadPanelBinary, IsCompatibleBinary, the same release asset) and
// owns the ordering itself: DB backup, swap, restart.
func runUpdate() error {
	initLogger()
	if err := database.InitDB(config.GetDBPath()); err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}

	var serverService service.ServerService
	fmt.Println(ansiProUI())
	upd, err := serverService.CheckPanelUpdate()
	if err != nil {
		return fmt.Errorf("could not check for updates: %w", err)
	}
	fmt.Printf("  Current: %s\n", upd.Current)
	fmt.Printf("  Latest:  %s\n", upd.Latest)
	if !upd.Available {
		fmt.Println("Already up to date, nothing to do.")
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve own path: %w", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = resolved
	}

	tmp := exe + ".new"
	fmt.Printf("Downloading %s (compressed, resumable) ...\n", service.PanelDownloadGZURL)
	tmp, err = service.DownloadPanelUpdate(context.Background(), exe, "")
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("download failed: %w", err)
	}
	if !service.IsCompatibleBinary(tmp) {
		_ = os.Remove(tmp)
		return fmt.Errorf("downloaded file is not a %s Linux binary (no valid '%s' asset?)",
			runtime.GOARCH, service.PanelAsset)
	}
	if !service.HasSQLiteSupport(tmp) {
		_ = os.Remove(tmp)
		return fmt.Errorf("downloaded binary lacks CGO/SQLite support — update via deploy.sh on the server instead")
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("could not make the downloaded binary executable: %w", err)
	}

	backup, err := backupPanelDBForUpdate(upd.Current)
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("DB backup failed: %w\nAborting before replacing the binary: an update without a good backup is not worth it.", err)
	}
	fmt.Printf("Backed up DB -> %s\n", backup)

	if err := service.CopyFile(exe, exe+".bak"); err == nil {
		_ = os.Chmod(exe+".bak", 0o755)
	} else {
		fmt.Fprintf(os.Stderr, "warning: could not keep a backup of the current binary: %v\n", err)
	}

	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing the binary failed: %w", err)
	}
	fmt.Printf("Installed %s -> %s\n", upd.Latest, exe)

	if err := exec.Command(exe, "install-menu").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not refresh the %s menu script: %v\n", service.MenuScriptPath, err)
	}

	var sd service.SystemdService
	unit := sd.GetServiceName()
	if exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil {
		fmt.Printf("Restarting %s ...\n", unit)
		if err := exec.Command("systemctl", "restart", unit).Run(); err != nil {
			return fmt.Errorf("restart failed: %w\nRestart it yourself: systemctl restart %s", err, unit)
		}
		fmt.Println("Done. The panel now runs the new binary.")
		return nil
	}

	fmt.Printf("The new binary is installed, but the unit %q is not active, so nothing was restarted.\n", unit)
	if ctlPing() {
		fmt.Println("A panel IS running outside systemd (its control socket answers): it keeps serving")
		fmt.Println("the OLD binary until you stop that process and start the new one.")
	} else {
		fmt.Printf("Start the panel when ready: systemctl start %s\n", unit)
	}
	return nil
}

// backupPanelDBForUpdate snapshots the DB next to itself, timestamped and tagged
// with the OUTGOING version, and returns the backup's path. deploy.sh:198-217 is
// the model: several updates each keep their own restore point, and a failed copy
// aborts the update rather than replacing the binary on a hope.
//
// service.backupPanelDB (the in-panel updater's) is not reused: it is best-effort
// and single-slot (vpn-ui_<version>.db), so a second update from the same version
// silently overwrites the only copy of the DB you would want back.
//
// Unlike deploy.sh we do not stop the panel first. Swapping the binary does not
// need it, and taking every VPN down for a file rename that only takes effect on
// the next restart would be a poor trade. That does mean a live panel may be
// writing: checkpointing the WAL into the main file and copying the sidecars
// alongside keeps the copied SET recoverable, which is the same bargain deploy.sh
// makes with its own sidecar copies.
func backupPanelDBForUpdate(fromVersion string) (string, error) {
	db := config.GetDBPath()
	if _, err := os.Stat(db); err != nil {
		return "", fmt.Errorf("database %s: %w", db, err)
	}
	dir := filepath.Join(filepath.Dir(db), "backups")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// Fold the WAL into the main DB so the copy is as close to a point-in-time
	// snapshot as a plain file copy can be.
	if gdb := database.GetDB(); gdb != nil {
		if sqlDB, err := gdb.DB(); err == nil {
			_, _ = sqlDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		}
	}
	if fromVersion == "" {
		fromVersion = "unknown"
	}
	dst := filepath.Join(dir, fmt.Sprintf("vpn-ui_%s_%s.db", fromVersion, time.Now().Format("20060102-150405")))
	if err := service.CopyFile(db, dst); err != nil {
		return "", fmt.Errorf("%s -> %s: %w", db, dst, err)
	}
	for _, side := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(db + side); err != nil {
			continue // checkpointed away or never created: nothing to copy
		}
		if err := service.CopyFile(db+side, dst+side); err != nil {
			return "", fmt.Errorf("%s -> %s: %w", db+side, dst+side, err)
		}
	}
	return dst, nil
}

// menuScript is the `vpn-ui` management menu, shipped INSIDE the binary it drives.
//
// Upstream installs its menu by curling raw.githubusercontent at `main`, which
// pins the tip of the default branch even when the box is running a tagged
// release, so an old install self-updates into a menu whose numbering does not
// match its own binary. Embedding removes the possibility: the script and the
// binary are one artifact, and `update` reinstalls the menu by running
// `install-menu` on the NEW binary. It also means deploy.sh can install the menu
// while piped from curl, with no second download.
//
//go:embed vpn-ui.sh
var menuScript []byte

// The Let's Encrypt / ACME client (pinned acme.sh, see build/acme/README.md),
// baked into the binary so real SSL works OFFLINE. obtain_letsencrypt_cert in
// vpn-ui.sh used to acquire it with `curl https://get.acme.sh | sh`, which fails on
// a box with no/blocked egress to get.acme.sh and left the panel on plain HTTP with
// only "acme.sh not found after install, skipping real SSL." The menu now extracts
// THIS copy and runs its --install locally; only the final --issue needs network.
//
//go:embed build/acme/acme.sh
var AcmeScript []byte

// The Cloudflare DNS-01 hook from the same pinned acme.sh release. acme.sh 3.1.4
// does NOT fetch a missing dnsapi plugin: `--dns dns_cf` just reports "Cannot find
// DNS API hook" and falls back to telling the operator to add the TXT record by
// hand, which is no flow at all. Bundling it keeps the Cloudflare-token option (and
// every wildcard certificate, which Let's Encrypt only issues over DNS-01) working
// on a box that cannot reach GitHub.
//
//go:embed build/acme/dnsapi/dns_cf.sh
var AcmeDnsCfHook []byte

// installAcmeScript implements `vpn-ui install-acme <path>`: write the embedded
// acme.sh client (0755) to <path>, plus the Cloudflare DNS hook as
// <dir>/dnsapi/dns_cf.sh. The management menu extracts it to a scratch dir and runs
// it as `--install`, so Let's Encrypt issuance no longer depends on fetching the
// client from the internet at deploy time.
//
// The hook goes in a `dnsapi` subdirectory because that is where acme.sh's own
// installer looks: `--install` copies `dnsapi/*` from the directory it is run in
// into $HOME/.acme.sh/dnsapi/, which is the only place _findHook reads at issue time.
func installAcmeScript(args []string) {
	if len(args) == 0 || args[0] == "" {
		fmt.Fprintln(os.Stderr, "usage: vpn-ui install-acme <path>")
		os.Exit(1)
	}
	if err := backend.WriteFileAtomic(args[0], AcmeScript, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to write the bundled acme.sh:", err)
		os.Exit(1)
	}
	hookDir := filepath.Join(filepath.Dir(args[0]), "dnsapi")
	if err := os.MkdirAll(hookDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to create the acme.sh dnsapi directory:", err)
		os.Exit(1)
	}
	if err := backend.WriteFileAtomic(filepath.Join(hookDir, "dns_cf.sh"), AcmeDnsCfHook, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to write the bundled Cloudflare DNS hook:", err)
		os.Exit(1)
	}
}

// runCloudflare implements `vpn-ui cf verify` and `vpn-ui cf zones`, the two
// Cloudflare lookups the menu's DNS-01 SSL path needs before it hands a token to
// acme.sh. Output is deliberately machine-readable (one zone per line, name TAB
// status) so the menu never parses JSON and no jq is required on the host.
//
// The token is read from CF_Token in the environment, NEVER from argv: a command
// line is world-readable through /proc/<pid>/cmdline, an environment is not. It is
// also the variable name acme.sh itself expects, so the menu exports it once.
func runCloudflare(args []string) error {
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("usage: CF_Token=... vpn-ui cf {verify|zones}")
	}
	token := os.Getenv("CF_Token")
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("CF_Token is not set in the environment")
	}

	switch args[0] {
	case "verify":
		status, err := service.VerifyCloudflareToken(token)
		if err != nil {
			return fmt.Errorf("Cloudflare rejected the API token: %w", err)
		}
		if status == "" {
			status = "active"
		}
		fmt.Printf("token verified (status: %s)\n", status)
	case "zones":
		zones, err := service.ListCloudflareZones(token)
		if err != nil {
			return fmt.Errorf("Cloudflare zone lookup failed: %w", err)
		}
		if len(zones) == 0 {
			return fmt.Errorf("the token is valid but can see no zones")
		}
		for _, zone := range zones {
			fmt.Printf("%s\t%s\n", zone.Name, zone.Status)
		}
	default:
		return fmt.Errorf("unknown argument for cf: %q (use verify or zones)", args[0])
	}
	return nil
}

// installMenuScript implements `vpn-ui install-menu [path]`: write the embedded
// menu to /usr/bin/vpn-ui (0755). deploy.sh runs it on both fresh install and
// update; `update` runs it again from the newly installed binary.
func installMenuScript(args []string) {
	dest := service.MenuScriptPath
	if len(args) > 0 && args[0] != "" {
		dest = args[0]
	}
	// WriteFileAtomic (temp file + rename) rather than a plain write, because the
	// target may be THE SCRIPT CURRENTLY RUNNING: the menu's own Update item calls
	// this via `vpn-ui-amd64 update`. bash reads a script lazily by offset from an
	// open fd, so overwriting it in place would feed the running shell the tail of a
	// different file. Renaming leaves the old inode intact for as long as bash holds
	// it open.
	if err := backend.WriteFileAtomic(dest, menuScript, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to install the management menu:", err)
		os.Exit(1)
	}
	fmt.Printf("Installed the pro-ui management menu -> %s (run: %s)\n", dest, filepath.Base(dest))
}

// ensureMenuInstalled writes the `vpn-ui` management menu to MenuScriptPath on panel
// startup when it is missing or out of date, so the `vpn-ui` command exists no matter
// how the panel was deployed. deploy.sh runs `install-menu` explicitly, but a manual
// launch (scp the binary, `setsid ./vpn-ui-amd64 &`) never does, so the command was
// simply absent on hand-deployed boxes.
//
// Compare-then-write: it only writes when the on-disk script differs from the embedded
// one, so a restart of an up-to-date panel touches nothing. Best-effort by design: a
// failure (read-only /usr/bin, not root) is logged and ignored. A panel that serves
// traffic without its convenience menu beats one that refused to boot over it. The
// atomic write (rename) is safe even if this exact file is the script currently being
// run: bash keeps its open inode, so it reads to the end of the old file.
func ensureMenuInstalled() {
	dest := service.MenuScriptPath
	if cur, err := os.ReadFile(dest); err == nil && bytes.Equal(cur, menuScript) {
		return
	}
	if err := backend.WriteFileAtomic(dest, menuScript, 0o755); err != nil {
		logger.Warning("could not install the pro-ui management menu at", dest, ":", err)
		return
	}
	logger.Info("installed the pro-ui management menu at", dest)
}

// applyCredential updates the first user's login from the CLI: both fields set both;
// only --pass keeps the current username; only --user keeps the current password hash
// (via SetFirstUsername) so the operator need not re-supply the password to rename.
func applyCredential(userService *service.UserService, username, password string) error {
	if username != "" && password != "" {
		return userService.UpdateFirstUser(username, password)
	}
	if password != "" { // password only — keep the current username
		cur, err := userService.GetFirstUser()
		if err != nil {
			return err
		}
		return userService.UpdateFirstUser(cur.Username, password)
	}
	// username only — keep the current password hash
	return userService.SetFirstUsername(username)
}

// resetSetting resets all panel settings to their default values.
func resetSetting() error {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Failed to initialize database:", err)
		return err
	}

	settingService := service.SettingService{}
	err = settingService.ResetSettings()
	if err != nil {
		fmt.Println("Failed to reset settings:", err)
		return err
	} else {
		fmt.Println("Settings successfully reset.")
	}
	return nil
}

// showSetting displays the current panel settings if show is true.
func showSetting(show bool) {
	if show {
		settingService := service.SettingService{}
		port, err := settingService.GetPort()
		if err != nil {
			fmt.Println("get current port failed, error info:", err)
		}

		webBasePath, err := settingService.GetBasePath()
		if err != nil {
			fmt.Println("get webBasePath failed, error info:", err)
		}

		certFile, err := settingService.GetCertFile()
		if err != nil {
			fmt.Println("get cert file failed, error info:", err)
		}
		keyFile, err := settingService.GetKeyFile()
		if err != nil {
			fmt.Println("get key file failed, error info:", err)
		}

		userService := service.UserService{}
		userModel, err := userService.GetFirstUser()
		if err != nil {
			fmt.Println("get current user info failed, error info:", err)
		}

		// GetFirstUser returns a NIL model together with that error (and on an empty
		// user table), so every dereference below has to be guarded. The unguarded
		// userModel.Username here panicked on exactly the failure the line above just
		// reported.
		if userModel == nil {
			fmt.Println("current username or password is empty")
		} else if userModel.Username == "" || userModel.Password == "" {
			fmt.Println("current username or password is empty")
		}

		fmt.Println("current panel settings as follows:")
		if certFile == "" || keyFile == "" {
			fmt.Println("Warning: Panel is not secure with SSL")
		} else {
			fmt.Println("Panel is secure with SSL")
		}

		hasDefaultCredential := userModel != nil &&
			userModel.Username == "admin" && crypto.CheckPasswordHash(userModel.Password, "admin")

		fmt.Println("hasDefaultCredential:", hasDefaultCredential)
		fmt.Println("port:", port)
		fmt.Println("webBasePath:", webBasePath)
	}
}

// updateTgbotEnableSts enables or disables the Telegram bot notifications based on the status parameter.
func updateTgbotEnableSts(status bool) {
	settingService := service.SettingService{}
	currentTgSts, err := settingService.GetTgbotEnabled()
	if err != nil {
		fmt.Println(err)
		return
	}
	logger.Infof("current enabletgbot status[%v],need update to status[%v]", currentTgSts, status)
	if currentTgSts != status {
		err := settingService.SetTgbotEnabled(status)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("SetTgbotEnabled[%v] success", status)
		}
	}
}

// updateTgbotSetting updates Telegram bot settings including token, chat ID, and runtime schedule.
func updateTgbotSetting(tgBotToken string, tgBotChatid string, tgBotRuntime string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Error initializing database:", err)
		return
	}

	settingService := service.SettingService{}

	if tgBotToken != "" {
		err := settingService.SetTgBotToken(tgBotToken)
		if err != nil {
			fmt.Printf("Error setting Telegram bot token: %v\n", err)
			return
		}
		logger.Info("Successfully updated Telegram bot token.")
	}

	if tgBotRuntime != "" {
		err := settingService.SetTgbotRuntime(tgBotRuntime)
		if err != nil {
			fmt.Printf("Error setting Telegram bot runtime: %v\n", err)
			return
		}
		logger.Infof("Successfully updated Telegram bot runtime to [%s].", tgBotRuntime)
	}

	if tgBotChatid != "" {
		err := settingService.SetTgBotChatId(tgBotChatid)
		if err != nil {
			fmt.Printf("Error setting Telegram bot chat ID: %v\n", err)
			return
		}
		logger.Info("Successfully updated Telegram bot chat ID.")
	}
}

// updateSetting updates various panel settings including port, credentials, base path, listen IP, and two-factor authentication.
func updateSetting(port int, username string, password string, webBasePath string, listenIP string, resetTwoFactor bool) error {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println("Database initialization failed:", err)
		return err
	}

	settingService := service.SettingService{}
	userService := service.UserService{}

	if port > 0 {
		err := settingService.SetPort(port)
		if err != nil {
			fmt.Println("Failed to set port:", err)
		} else {
			fmt.Printf("Port set successfully: %v\n", port)
		}
	}

	if username != "" || password != "" {
		err := userService.UpdateFirstUser(username, password)
		if err != nil {
			fmt.Println("Failed to update username and password:", err)
		} else {
			fmt.Println("Username and password updated successfully")
		}
	}

	if webBasePath != "" {
		err := settingService.SetBasePath(webBasePath)
		if err != nil {
			fmt.Println("Failed to set base URI path:", err)
		} else {
			fmt.Println("Base URI path set successfully")
		}
	}

	if resetTwoFactor {
		// Two-factor moved from one panel-wide setting onto each admin's own row, so
		// clearing the old settings keys does nothing at all. This switch is the only
		// recovery path for a lost authenticator (login needs the code, and disabling
		// it through the UI needs the code too), so it must act on the real store or
		// it strands the operator while printing success.
		var userService service.UserService
		user, err := userService.GetFirstUser()
		if err != nil {
			fmt.Println("Failed to reset two-factor authentication:", err)
		} else if err := userService.SetTwoFactor(user.Id, false, ""); err != nil {
			fmt.Println("Failed to reset two-factor authentication:", err)
		} else {
			fmt.Printf("Two-factor authentication reset successfully for %q\n", user.Username)
		}
	}

	if listenIP != "" {
		err := settingService.SetListen(listenIP)
		if err != nil {
			fmt.Println("Failed to set listen IP:", err)
		} else {
			fmt.Printf("listen %v set successfully", listenIP)
		}
	}

	return nil
}

// generateSelfSignedPanelCert generates a self-signed TLS certificate for the
// panel, writes it next to the binary/DB (config dir + /cert), and points the
// panel's webCertFile/webKeyFile at it so the web server serves HTTPS. Invoked by
// `vpn-ui cert -selfsign` (used by deploy.sh's fresh-install HTTPS option). The
// cert carries the server's public IP as a SAN; browsers still warn on the
// self-signed issuer, which is expected.
func generateSelfSignedPanelCert() {
	dir := filepath.Join(config.GetDBFolderPath(), "cert")
	ip := service.GetServerIPv4()
	certPath, keyPath, err := service.GeneratePanelSelfSignedCert(dir, ip)
	if err != nil {
		fmt.Fprintln(os.Stderr, "self-signed cert generation failed:", err)
		os.Exit(1)
	}
	fmt.Printf("Generated self-signed panel certificate:\n  cert: %s\n  key:  %s\n", certPath, keyPath)
	// updateCert stores the paths in webCertFile/webKeyFile, which flips the web
	// server to HTTPS on next start. It does NOT touch the subscription server:
	// generating an identity for the panel says nothing about whether the links
	// operators hand out should be served over TLS, and this one is self-signed, so
	// every client fetching a subscription over it would have to be told to ignore
	// the warning.
	updateCert(certPath, keyPath)
}

// certPairStorable reports whether a pair typed on the command line may be stored,
// printing the refusal itself when it may not.
//
// Validated BEFORE the database is even opened, because a refused command should
// leave nothing behind, not even a freshly initialised DB file.
//
// The settings form already validates through AllSetting.CheckValid
// (web/entity/entity.go:140-152); the CLI did not, and that asymmetry is the bug.
// Without this, `vpn-ui cert -webCert ...` accepts a mismatched or unreadable pair
// and the damage only surfaces at the NEXT restart, where web.go:541-556 logs one
// line and silently comes up on plain HTTP. A silent downgrade to HTTP hours after
// the command that caused it is not a failure anyone connects back to this command.
//
// service.ValidateCertPair is deliberately the same check the certificate store
// uses to gate activation (tls.LoadX509KeyPair PLUS a key-matches-leaf test),
// rather than a second, weaker copy of tls.LoadX509KeyPair here.
//
// Clearing (both empty) skips the check: that is a valid request to stop serving
// TLS, and there is nothing to validate.
func certPairStorable(publicKey string, privateKey string) bool {
	if privateKey != "" && publicKey != "" {
		if err := service.ValidateCertPair(publicKey, privateKey); err != nil {
			fmt.Printf("refusing to store this certificate: %v\n  cert: %s\n  key:  %s\nNothing was changed.\n", err, publicKey, privateKey)
			return false
		}
	}
	return true
}

// certPairComplete enforces the both-or-neither rule: a certificate without its key
// is not a thing any listener can serve, and storing half a pair is how a listener
// comes up on plain HTTP with nothing in the log to explain it.
func certPairComplete(publicKey string, privateKey string) bool {
	if (privateKey != "" && publicKey != "") || (privateKey == "" && publicKey == "") {
		return true
	}
	fmt.Println("both public and private key should be entered.")
	return false
}

// certRestartNote is the last line of every `vpn-ui cert` invocation. Both listeners
// read their paths out of the settings once, when they are built, so a change made
// here is invisible until the panel starts again. Saying so is the difference
// between an operator who restarts and one who reports that the command did nothing.
const certRestartNote = "Both listeners read these paths when they start, so this takes effect the next time the panel starts."

// updateCert points the PANEL's listener at a certificate pair. `vpn-ui cert
// -webCert <cert> -webCertKey <key>`, and the empty pair clears it.
func updateCert(publicKey string, privateKey string) {
	if !certPairStorable(publicKey, privateKey) {
		return
	}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	if !certPairComplete(publicKey, privateKey) {
		return
	}

	settingService := service.SettingService{}

	// The subscription server can now hold a DIFFERENT certificate from the panel
	// (see SSLService.Assign). Read where it points BEFORE the panel pair moves, so
	// a deliberate split survives this command.
	//
	// AN EMPTY subCertFile IS NOT "the subscription server follows the panel". It
	// used to count as one, and that is how a flag named -webCert came to switch a
	// subscription server on: subCertFile is "" on every fresh install (its default
	// in web/service/setting.go), and both installers run this command as part of
	// one, vpn-ui.sh with `-webCert .../fullchain.pem` after acme.sh and deploy.sh
	// with `-selfsign`. So every install mounted the panel's certificate on a
	// subscription listener nobody had asked to serve TLS. Empty means the operator
	// never gave that listener a certificate, and a flag named -webCert is not them
	// asking for one; -subCert is.
	oldPanelCert, _ := settingService.GetCertFile()
	oldSubCert, _ := settingService.GetSubCertFile()
	subCert := strings.TrimSpace(oldSubCert)
	subFollowsPanel := subCert != "" &&
		filepath.Clean(subCert) == filepath.Clean(strings.TrimSpace(oldPanelCert))

	err = settingService.SetCertFile(publicKey)
	if err != nil {
		fmt.Println("set certificate public key failed:", err)
	} else {
		fmt.Println("set certificate public key success")
	}

	err = settingService.SetKeyFile(privateKey)
	if err != nil {
		fmt.Println("set certificate private key failed:", err)
	} else {
		fmt.Println("set certificate private key success")
	}

	// Only carry the subscription server along when it was already serving the
	// panel's certificate, which is the one case where leaving it behind would be
	// the surprise: those two settings named one file, and now one of them would
	// name a file this command has just replaced. Every other case says out loud
	// what it did not touch, because a command that quietly reaches a second
	// listener is the bug this used to be.
	if !subFollowsPanel {
		if subCert == "" {
			fmt.Println("subscription server: NOT changed, it has no certificate of its own and keeps serving plain HTTP")
			fmt.Println("  give it one with: vpn-ui cert -subCert <cert> -subCertKey <key>")
		} else {
			fmt.Printf("subscription server: NOT changed, it stays on its own certificate (%s)\n", subCert)
		}
		fmt.Println(certRestartNote)
		return
	}
	fmt.Println("subscription server: it was pointed at the same file as the panel, so it follows this change")

	err = settingService.SetSubCertFile(publicKey)
	if err != nil {
		fmt.Println("set certificate for subscription public key failed:", err)
	} else {
		fmt.Println("set certificate for subscription public key success")
	}

	err = settingService.SetSubKeyFile(privateKey)
	if err != nil {
		fmt.Println("set certificate for subscription private key failed:", err)
	} else {
		fmt.Println("set certificate for subscription private key success")
	}
	fmt.Println(certRestartNote)
}

// certCommandTargets decides which listeners a `vpn-ui cert` invocation moves, from
// the set of flags that were actually typed rather than from their values.
//
// A bare `vpn-ui cert` keeps meaning "clear the panel's pair", which is what it has
// always meant and what -reset spells out. The one case that skips the panel is a
// command that named a subscription flag and no panel flag: there, moving the panel
// would mean clearing it, and nobody setting the subscription server's certificate
// is asking for the panel's to be thrown away.
func certCommandTargets(typed map[string]bool) (panel bool, sub bool) {
	sub = typed["subCert"] || typed["subCertKey"]
	panel = !sub || typed["webCert"] || typed["webCertKey"]
	return panel, sub
}

// updateSubCert points the SUBSCRIPTION server's listener at a certificate pair,
// and nothing else. `vpn-ui cert -subCert <cert> -subCertKey <key>`, and the empty
// pair clears it.
//
// It exists because the two listeners are separate (sub/sub.go builds its own from
// subCertFile/subKeyFile) and the CLI could only ever move the panel's. That left
// the panel's own command as the only way a script could put TLS on the
// subscription server, which it did by covering both listeners at once whether or
// not anyone wanted the second one. Splitting the flags is what lets the panel's
// stop doing that: an operator who genuinely wants the subscription server on a
// certificate now has a flag that says so.
//
// Validation is the panel's, verbatim. A bad pair degrades this listener to plain
// HTTP the same way, and it degrades it where far fewer people are looking.
func updateSubCert(publicKey string, privateKey string) {
	if !certPairStorable(publicKey, privateKey) {
		return
	}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	if !certPairComplete(publicKey, privateKey) {
		return
	}

	settingService := service.SettingService{}

	err = settingService.SetSubCertFile(publicKey)
	if err != nil {
		fmt.Println("set certificate for subscription public key failed:", err)
	} else {
		fmt.Println("set certificate for subscription public key success")
	}

	err = settingService.SetSubKeyFile(privateKey)
	if err != nil {
		fmt.Println("set certificate for subscription private key failed:", err)
	} else {
		fmt.Println("set certificate for subscription private key success")
	}

	panelCert, _ := settingService.GetCertFile()
	if strings.TrimSpace(panelCert) == "" {
		fmt.Println("panel: NOT changed, it has no certificate and keeps serving plain HTTP")
	} else {
		fmt.Printf("panel: NOT changed, it stays on %s\n", strings.TrimSpace(panelCert))
	}
	fmt.Println(certRestartNote)
}

// GetCertificate displays the current SSL certificate settings if getCert is true.
func GetCertificate(getCert bool) {
	if getCert {
		settingService := service.SettingService{}
		certFile, err := settingService.GetCertFile()
		if err != nil {
			fmt.Println("get cert file failed, error info:", err)
		}
		keyFile, err := settingService.GetKeyFile()
		if err != nil {
			fmt.Println("get key file failed, error info:", err)
		}

		fmt.Println("cert:", certFile)
		fmt.Println("key:", keyFile)
	}
}

// GetListenIP displays the current panel listen IP address if getListen is true.
func GetListenIP(getListen bool) {
	if getListen {

		settingService := service.SettingService{}
		ListenIP, err := settingService.GetListen()
		if err != nil {
			log.Printf("Failed to retrieve listen IP: %v", err)
			return
		}

		fmt.Println("listenIP:", ListenIP)
	}
}

// migrateDb performs database migration operations for the pro-ui panel.
// revertAccounts is the operator's way out of the accounts layer.
//
// Safe by construction for the panels that would want it: settings.clients is
// still the truth, so on a panel where every account is on ONE inbound this is
// exactly a no-op for the data plane. Every account keeps its entry, its
// credentials and its tunnel address; only the two index tables and the migrated
// flag go, and the next start simply rebuilds them (or does not, if the operator
// stays on an older binary).
//
// It refuses while any account is on SEVERAL inbounds, because there is no
// non-destructive answer for those. See AccountService.RevertAccounts.
func revertAccounts() {
	if err := database.InitDB(config.GetDBPath()); err != nil {
		log.Fatal(err)
	}
	accountService := service.AccountService{}
	accounts, memberships, err := accountService.RevertAccounts()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Reverted: removed %d account(s) and %d membership(s).\n", accounts, memberships)
	fmt.Println("settings.clients was not touched, so every account keeps its entry, credentials and address.")
	fmt.Println("Restart the panel to continue on the legacy client model.")
}

func migrateDb() {
	inboundService := service.InboundService{}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Start migrating database...")
	inboundService.MigrateDB()
	fmt.Println("Migration done!")
}

// importDb imports a stock 3x-ui (or vpn-ui) backup database over the current one,
// keeping THIS panel's reachability/identity settings (port, path, TLS, session
// secret, RADIUS secret, provisioning state). Everything else, the operator's
// inbounds/clients/traffic/admins/subscription content, comes across from the
// backup. deploy.sh calls this on a fresh install when the operator points it at a
// 3x-ui backup; it is also available standalone. Usage: vpn-ui import --from <path>
func importDb() {
	importCmd := flag.NewFlagSet("import", flag.ExitOnError)
	var from string
	importCmd.StringVar(&from, "from", "", "path to the 3x-ui/vpn-ui backup .db to import")
	_ = importCmd.Parse(os.Args[2:])
	if from == "" && importCmd.NArg() > 0 {
		from = importCmd.Arg(0) // also accept `vpn-ui import <path>`
	}
	if from == "" {
		fmt.Fprintln(os.Stderr, "usage: vpn-ui import --from <path-to-backup.db>")
		os.Exit(1)
	}
	src, err := os.Open(from)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import: cannot open %s: %v\n", from, err)
		os.Exit(1)
	}
	defer src.Close()

	// A current DB has to exist so its settings can be snapshotted before the swap.
	// On a fresh install this creates the defaults we then preserve; on an existing
	// one it opens the live DB.
	if err := database.InitDB(config.GetDBPath()); err != nil {
		fmt.Fprintf(os.Stderr, "import: %v\n", err)
		os.Exit(1)
	}
	var serverService service.ServerService
	// activate=false: the panel is not running here, so do not regenerate configs or
	// restart Xray; the panel's own startup brings the data plane up on the new data.
	report, err := serverService.ImportForeignDB(src, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "import failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Imported %d inbound(s), %d client account(s), %d admin account(s).\n",
		report.Inbounds, report.Clients, report.Admins)
	fmt.Printf("Kept this panel's own settings (%d key(s): port, path, TLS, secrets).\n",
		len(report.PreservedSettings))
	fmt.Println("Log in with the username and password from the imported panel.")
}

// readRadiusSecret returns the RADIUS shared secret used by the OpenVPN auth/connect
// /disconnect hooks. Canonical source is the panel DB (settings key `radiusSecret`,
// written by getOrCreateRadiusSecret on startup): these hooks are separate short-lived
// processes that don't hold the panel's in-memory secret, and the DB is the single
// source of truth. The legacy /etc/ppp/radius/servers file is only a fallback — it is
// written solely by l2tp/pptp setup, so on an OpenVPN-only box it doesn't exist, which
// is why reading only that file rejected every OpenVPN login ("RADIUS secret not found").
func readRadiusSecret() string {
	if secret, err := database.GetSettingValue(config.GetDBPath(), "radiusSecret"); err == nil && secret != "" {
		return secret
	}
	// Fallback: the radcli servers file, present only when l2tp/pptp is configured.
	data, err := os.ReadFile("/etc/ppp/radius/servers")
	if err != nil {
		return ""
	}
	// Format: "127.0.0.1\t{secret}\n"
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "127.0.0.1" {
			return fields[1]
		}
	}
	return ""
}

// openvpnAuth handles OpenVPN auth-user-pass-verify via RADIUS PAP.
// Usage: vpn-ui openvpn-auth {inbound_id} {credentials_file}
// The credentials file has username on line 1, password on line 2.
func openvpnAuth() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: vpn-ui openvpn-auth <inbound_id> <cred_file>")
		os.Exit(1)
	}

	inboundId, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid inbound_id:", os.Args[2])
		os.Exit(1)
	}

	credFile := os.Args[3]
	data, err := os.ReadFile(credFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read credentials file:", err)
		os.Exit(1)
	}

	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(lines) < 2 {
		fmt.Fprintln(os.Stderr, "credentials file must have username and password on separate lines")
		os.Exit(1)
	}
	username := strings.TrimSpace(lines[0])
	password := strings.TrimSpace(lines[1])

	secret := readRadiusSecret()
	if secret == "" {
		fmt.Fprintln(os.Stderr, "RADIUS secret not found")
		os.Exit(1)
	}

	// Send PAP Access-Request
	packet := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2865.UserName_SetString(packet, username)
	rfc2865.UserPassword_SetString(packet, password)
	rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))

	resp, err := radius.Exchange(context.Background(), packet, "127.0.0.1:1812")
	if err != nil {
		fmt.Fprintln(os.Stderr, "RADIUS exchange failed:", err)
		os.Exit(1)
	}

	if resp.Code == radius.CodeAccessAccept {
		os.Exit(0) // Accept
	}
	os.Exit(1) // Reject
}

// openvpnConnect handles OpenVPN client-connect via RADIUS Acct-Start.
// ovpnLeaseBlockIP implements the OpenVPN side of the per-account "User Limit"
// block allocation. When the panel has published blocks-<proto>/<CN> for this
// inbound (User Limit K>=2), it leases the lowest free IP inside that account's
// block and returns (ip, serverBlockMask, false) for a `ifconfig-push`. Returns
// ("","",false) for K==1 inbounds (no block file) — the caller keeps the pool IP.
//
// When the block is full the User Limit Strategy decides: "accept" force-kills the
// account's oldest device via the management socket and reuses its IP (returns that
// ip); "reject" (default) returns ("","",true) so the caller fails the connect and
// OpenVPN refuses the device.
//
// "Free" = not currently held by an established client (OpenVPN's own status
// file, authoritative) and not held by a fresh lease (a short-TTL marker that
// bridges the gap between this connect and the client appearing in the status
// file). Leaked leases self-expire, so no long-lived bookkeeping is needed.
// ovpnLeaseReclaimGrace is the minimum age of a gap-lease before it may be
// reclaimed for a new dial. OpenVPN rewrites the status file every 5s, so any
// live device is listed within 5s of connecting; a lease older than this that is
// still absent from the status is therefore an abandoned ghost — safe to reclaim
// without stealing a slot from a device that is merely mid-handshake.
const ovpnLeaseReclaimGrace = 10 * time.Second

func ovpnLeaseBlockIP(inboundId int, username, poolIP, sessionKey string) (string, string, bool) {
	proto := "udp"
	if strings.HasPrefix(poolIP, "10.3.") {
		proto = "tcp"
	}
	dir := fmt.Sprintf("/etc/openvpn/server-%d", inboundId)
	blockFile := filepath.Join(dir, "blocks-"+proto, username)
	data, err := os.ReadFile(blockFile)
	if err != nil {
		return "", "", false // no block published -> K==1, keep the pool IP
	}
	parts := strings.Fields(strings.TrimSpace(string(data)))
	if len(parts) < 2 {
		return "", "", false
	}
	// Block file format: "<serverBlockMask> <ip1> <ip2> ..." — the account's K
	// device IPs (an explicit list, so the block size need not be a power of two).
	mask := parts[0]
	candidates := parts[1:]

	// Serialize concurrent client-connect hooks for this inbound+proto. They run as
	// separate short-lived processes sharing the lease dir, so without a lock two
	// devices dialing at once can both read the block as free and lease the SAME IP
	// (an over-admit / duplicate-IP race). An exclusive flock makes the whole
	// read-decide-write below atomic across hooks; it releases when this process exits.
	if lf, lerr := os.OpenFile(filepath.Join(dir, "connect-"+proto+".lock"), os.O_CREATE|os.O_RDWR, 0644); lerr == nil {
		defer lf.Close()
		if syscall.Flock(int(lf.Fd()), syscall.LOCK_EX) == nil {
			defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
		}
	}

	statusPath := fmt.Sprintf("/var/run/openvpn/status-%d-%s.log", inboundId, proto)
	liveStatus := ovpnStatusIPs(statusPath) // devices OpenVPN currently reports connected
	inUse := make(map[string]bool, len(liveStatus))
	for ip := range liveStatus {
		inUse[ip] = true
	}

	// Addresses openvpn has told us are free but the status file still shows connected
	// (it is rewritten only every 5s). Applied after the lease scan below, so a new
	// device that has already leased one of them still counts as holding it.
	released := ovpnReleasedIPs(dir, proto)

	leaseDir := filepath.Join(dir, "leases-"+proto)
	_ = os.MkdirAll(leaseDir, 0755)
	now := time.Now()
	leaseAge := make(map[string]time.Duration) // block IP -> age of its gap-lease
	if entries, e := os.ReadDir(leaseDir); e == nil {
		for _, ent := range entries {
			p := filepath.Join(leaseDir, ent.Name())
			fi, se := os.Stat(p)
			if se != nil {
				continue
			}
			if now.Sub(fi.ModTime()) > 30*time.Second {
				os.Remove(p) // stale gap-lease past its TTL
				continue
			}
			inUse[ent.Name()] = true // lease file is named by the leased IP
			leaseAge[ent.Name()] = now.Sub(fi.ModTime())
		}
	}

	// A released address is only still in use if something leased it since: the release
	// came from openvpn itself, the status entry behind it is just stale.
	for ip := range released {
		if _, leased := leaseAge[ip]; !leased {
			delete(inUse, ip)
			delete(liveStatus, ip)
		}
	}

	// User Limit K is per ACCOUNT, not per transport. Count this transport's occupied
	// block slots PLUS the account's devices on the OTHER transport (which draws on the
	// same K budget), so an account that enables both udp and tcp can't run K devices on
	// each for 2*K total. The other transport is only consulted when its block exists.
	usedCount := 0
	for _, ip := range candidates {
		if inUse[ip] {
			usedCount++
		}
	}
	otherProto := "tcp"
	if proto == "tcp" {
		otherProto = "udp"
	}
	if oData, oErr := os.ReadFile(filepath.Join(dir, "blocks-"+otherProto, username)); oErr == nil {
		if oIPs := strings.Fields(strings.TrimSpace(string(oData))); len(oIPs) >= 2 {
			oStatus := ovpnStatusIPs(fmt.Sprintf("/var/run/openvpn/status-%d-%s.log", inboundId, otherProto))
			oLease := ovpnLeasedIPs(filepath.Join(dir, "leases-"+otherProto))
			for _, ip := range oIPs[1:] { // skip the mask
				if oStatus[ip] || oLease[ip] {
					usedCount++
				}
			}
		}
	}

	// (1) A free slot for this new device — only while the account is under K in total.
	if usedCount < len(candidates) {
		for _, ip := range candidates {
			if inUse[ip] {
				continue
			}
			ovpnWriteLease(leaseDir, ip, sessionKey)
			ovpnClearRelease(dir, proto, ip)
			return ip, mask, false
		}
	}

	// The block is full — but a gap-lease can outlive its device by up to 30s, so "full"
	// may be an illusion.
	//
	// Reclaiming a slot pinned ONLY by a stale gap-lease is cleanup, not admission, so it
	// happens for EITHER strategy: a ghost is a lease with no device behind it, and
	// handing its address to a new dial keeps the number of LIVE devices within K either
	// way. This used to sit inside the "accept" branch below, which made a "reject"
	// inbound refuse an account's own redial (AUTH_FAILED, since a failing client-connect
	// script is reported to the client as an auth failure) for as long as the previous
	// lease lived. Any dial that does not complete leaves such a lease, so on a
	// reject inbound a client that dropped and came back looked permanently broken while
	// its User Limit was never actually exceeded.
	//
	// A ghost = a lease older than the grace whose IP is NOT in the status. OpenVPN
	// rewrites the status every 5s, so any real device is listed within 5s of connecting;
	// a >grace lease still absent from the status is abandoned, not a device merely
	// mid-handshake. Reclaim the OLDEST such ghost.
	var ghostIP string
	var ghostAge time.Duration
	for _, ip := range candidates {
		if liveStatus[ip] {
			continue // a genuinely connected device — never a ghost
		}
		if age, leased := leaseAge[ip]; leased && age > ovpnLeaseReclaimGrace && age > ghostAge {
			ghostIP, ghostAge = ip, age
		}
	}
	if ghostIP != "" {
		ovpnWriteLease(leaseDir, ghostIP, sessionKey)
		ovpnClearRelease(dir, proto, ghostIP)
		return ghostIP, mask, false
	}

	// Past that, the block really is held by live devices. "accept": evict the account's
	// oldest device and take its address. "reject" (default): refuse.
	if ovpnReadStrategy(dir, proto) == "accept" {
		// A real device-cap hit: evict the oldest LIVE device and reuse its IP. The kill
		// MUST happen AFTER this hook returns — client-connect runs synchronously and
		// blocks OpenVPN's management loop — so hand it to the detached openvpn-evict
		// helper. Killing by the pre-captured real address hits the OLD device.
		victimIP, victimRAddr := ovpnOldestFromStatus(statusPath, candidates)
		if victimIP == "" {
			// The block is full by leases, but no device is in the (up to 5s-stale)
			// status file yet, so it can't name a victim. Fall back to the OLDEST
			// gap-lease and let the detached evictor kill whoever holds that IP via the
			// LIVE management socket (openvpn-evict queries `status 3` when given no real
			// address). WITHOUT this, "accept" wrongly behaved like "reject" for any
			// device dialing within ~5s of the incumbents (the status hadn't flushed, so
			// the eviction never fired) — the "accept always rejects" bug.
			victimIP = oldestLeasedIP(leaseAge)
			if victimIP == "" {
				return "", "", true // genuinely nothing leased to reuse — refuse
			}
		}
		ovpnSpawnEvict(inboundId, proto, victimIP, victimRAddr)
		ovpnWriteLease(leaseDir, victimIP, sessionKey)
		ovpnClearRelease(dir, proto, victimIP)
		return victimIP, mask, false
	}
	return "", "", true // reject the new device
}

// oldestLeasedIP returns the block IP holding the oldest gap-lease (the account's
// longest-connected device — the "accept" eviction victim when the status file is too
// stale to name one), or "" when there are no leases.
func oldestLeasedIP(leaseAge map[string]time.Duration) string {
	var ip string
	oldest := time.Duration(-1)
	for k, age := range leaseAge {
		if age > oldest {
			oldest, ip = age, k
		}
	}
	return ip
}

// ovpnWriteLease records a gap-lease file named by the leased block IP, storing the
// device's pool IP as content so the disconnect hook can find and free it by pool IP.
func ovpnWriteLease(leaseDir, blockIP, sessionKey string) {
	_ = os.WriteFile(filepath.Join(leaseDir, blockIP), []byte(sessionKey), 0644)
}

// ovpnSessionKey identifies ONE device session, for matching a lease at disconnect back
// to the connect that wrote it.
//
// It must not be ifconfig_pool_remote_ip, which is what this used to be: every device on
// an inbound gets pushed a block address instead of the pool address, so openvpn keeps
// handing the SAME first pool address (the block's .2) to every client, and every lease
// file ended up holding that one value. Removal then matched the first lease in directory
// order rather than the disconnecting device's, which
//   - left the departing device's own lease behind, so on a "reject" inbound its redial
//     was refused as if its User Limit were full,
//   - freed a still-live device's lease, letting the account exceed its User Limit, and
//   - rebuilt the Acct-Stop session id from another device's address, so usage landed on
//     the wrong session ("acct-stop stale — ip=… reassigned to a live session").
//
// trusted_ip:trusted_port is the client's real transport address, unique per session and
// reported identically to the connect and disconnect hooks.
func ovpnSessionKey() string {
	ip, port := os.Getenv("trusted_ip"), os.Getenv("trusted_port")
	if ip == "" {
		ip = os.Getenv("trusted_ip6")
	}
	if ip == "" {
		// No real address in the environment: fall back to the pool address, which is
		// what the old scheme used. Still better than an empty key.
		return os.Getenv("ifconfig_pool_remote_ip")
	}
	if port == "" {
		return ip
	}
	return ip + ":" + port
}

// ovpnLeasedIPs returns the set of block IPs currently gap-leased in a transport's
// lease dir (fresh leases only; entries past the 30s TTL are ignored). Used to count
// the other transport's occupancy toward the shared per-account K budget.
func ovpnLeasedIPs(leaseDir string) map[string]bool {
	set := map[string]bool{}
	entries, err := os.ReadDir(leaseDir)
	if err != nil {
		return set
	}
	now := time.Now()
	for _, ent := range entries {
		fi, e := os.Stat(filepath.Join(leaseDir, ent.Name()))
		if e != nil || now.Sub(fi.ModTime()) > 30*time.Second {
			continue
		}
		set[ent.Name()] = true
	}
	return set
}

// ovpnRemoveLeaseBySession removes the gap-lease this device session holds (leases are
// named by block IP and hold the session key, see ovpnSessionKey) and returns the leased
// block IP, or "" if none matches. Called on client-disconnect so the slot frees
// immediately instead of lingering until the lease TTL, and so the Acct-Stop can be
// keyed by the same leased IP the connect hook used. A lease written by an older build
// holds a pool address instead and simply will not match: it ages out on the TTL.
func ovpnRemoveLeaseBySession(leaseDir, sessionKey string) string {
	entries, err := os.ReadDir(leaseDir)
	if err != nil {
		return ""
	}
	for _, ent := range entries {
		p := filepath.Join(leaseDir, ent.Name())
		content, e := os.ReadFile(p)
		if e == nil && sessionKey != "" && strings.TrimSpace(string(content)) == sessionKey {
			_ = os.Remove(p)
			return ent.Name()
		}
	}
	return ""
}

// ovpnReleaseTTL is how long a release marker counts. It only has to outlive the status
// file's write interval (status ... 5), with room for a slow rewrite.
const ovpnReleaseTTL = 15 * time.Second

// ovpnWriteRelease records that openvpn just told us a device left this block address.
//
// The status file is rewritten every 5s, so for a few seconds after a disconnect the
// departed device is still listed as connected, and a block whose addresses all look
// occupied is refused: an account that dropped and redialled straight away was answered
// with AUTH_FAILED although its User Limit was not reached. The management socket would
// give the live table, but client-connect runs INSIDE openvpn's event loop (which is why
// the evictor is a detached helper), so asking it from the hook would deadlock until the
// timeout. The disconnect hook already knows exactly which address was freed, so it says
// so here and the connect hook believes it over the stale file.
func ovpnWriteRelease(dir, proto, blockIP string) {
	if blockIP == "" {
		return
	}
	relDir := filepath.Join(dir, "released-"+proto)
	if err := os.MkdirAll(relDir, 0755); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(relDir, blockIP), nil, 0644)
}

// ovpnReleasedIPs returns the block IPs released within the TTL, expiring older markers.
func ovpnReleasedIPs(dir, proto string) map[string]bool {
	set := map[string]bool{}
	relDir := filepath.Join(dir, "released-"+proto)
	entries, err := os.ReadDir(relDir)
	if err != nil {
		return set
	}
	now := time.Now()
	for _, ent := range entries {
		p := filepath.Join(relDir, ent.Name())
		fi, serr := os.Stat(p)
		if serr != nil {
			continue
		}
		if now.Sub(fi.ModTime()) > ovpnReleaseTTL {
			os.Remove(p)
			continue
		}
		set[ent.Name()] = true
	}
	return set
}

// ovpnClearRelease drops a release marker once the address is handed out again.
func ovpnClearRelease(dir, proto, blockIP string) {
	os.Remove(filepath.Join(dir, "released-"+proto, blockIP))
}

// ovpnReadStrategy returns the inbound's User Limit Strategy ("accept", else the
// default "reject") from the panel-published strategy-<proto> file.
func ovpnReadStrategy(dir, proto string) string {
	data, err := os.ReadFile(filepath.Join(dir, "strategy-"+proto))
	if err != nil {
		return "reject"
	}
	if strings.TrimSpace(string(data)) == "accept" {
		return "accept"
	}
	return "reject"
}

// ovpnOldestFromStatus reads the OpenVPN status-version 3 FILE and returns the
// virtual IP and client-ID (among ips) of the client connected longest, or ("","")
// if none appear yet. The connect hook uses the file (not the live management
// socket) to pick the eviction victim, because while the hook runs OpenVPN's
// management loop is blocked (see openvpnEvict).
func ovpnOldestFromStatus(statusPath string, ips []string) (ip, raddr string) {
	want := make(map[string]bool, len(ips))
	for _, w := range ips {
		want[w] = true
	}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return "", ""
	}
	bestSince := int64(1) << 62
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CLIENT_LIST\t") {
			continue
		}
		// status v3: [2]RealAddr [3]VirtualAddr [8]ConnectedSince(time_t)
		f := strings.Split(line, "\t")
		if len(f) <= 8 || !want[f[3]] {
			continue
		}
		if since, perr := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); perr == nil && since < bestSince {
			bestSince, ip, raddr = since, f[3], strings.TrimSpace(f[2])
		}
	}
	return ip, raddr
}

// ovpnSpawnEvict launches a detached `openvpn-evict` helper that disconnects the
// victim client once OpenVPN is servicing its management socket again. Fire-and-
// forget: the connect hook must not wait on it. raddr is the victim's real address
// (IP:port — the unambiguous per-client kill key); ip is the fallback when the
// status file had no entry yet.
func ovpnSpawnEvict(inboundId int, proto, ip, raddr string) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe, "openvpn-evict", strconv.Itoa(inboundId), proto, ip, raddr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // survive the hook exiting
	_ = cmd.Start()                                      // no Wait: detached
}

// openvpnEvict runs detached from the (synchronous, management-blocking) client-
// connect hook. It waits for that hook to return so OpenVPN resumes servicing its
// management socket, then disconnects the victim via `kill <real-address>` (the
// classic per-client kill — `client-kill <CID>` only applies to deferred-auth
// clients). The new client reuses the victim's VIRTUAL IP, but real addresses are
// unique, so this hits the old device, not the one just admitted. Falls back to the
// OLDEST client on <ip> when no real address was pre-captured.
// Usage: vpn-ui openvpn-evict <id> <proto> <ip> [real-address]
func openvpnEvict() {
	if len(os.Args) < 5 {
		return
	}
	inboundId, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid inbound_id:", err)
		return
	}
	proto := os.Args[3]
	targetIP := os.Args[4]
	raddr := ""
	if len(os.Args) >= 6 {
		raddr = os.Args[5]
	}
	time.Sleep(1500 * time.Millisecond) // let the connect hook return first

	sock := fmt.Sprintf("/var/run/openvpn/mgmt-%d-%s.sock", inboundId, proto)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	if raddr == "" {
		// No pre-captured real address: query live and pick the OLDEST client on
		// targetIP (min connected-since) so the just-admitted client (newest) is
		// never the one killed when two share the virtual IP.
		if _, err := fmt.Fprint(conn, "status 3\n"); err != nil {
			return
		}
		bestSince := int64(1) << 62
		for {
			line, rerr := reader.ReadString('\n')
			if s := strings.TrimRight(line, "\r\n"); s != "" {
				if strings.HasPrefix(s, "CLIENT_LIST\t") {
					f := strings.Split(s, "\t")
					if len(f) > 8 && f[3] == targetIP {
						if since, perr := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); perr == nil && since < bestSince {
							bestSince, raddr = since, strings.TrimSpace(f[2])
						}
					}
				}
				if s == "END" {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
	}
	if raddr == "" {
		return
	}
	fmt.Fprintf(conn, "kill %s\n", raddr)
	// Read past the management greeting / async lines until the kill verdict so the
	// command is flushed and processed before we close the socket.
	for i := 0; i < 20; i++ {
		line, rerr := reader.ReadString('\n')
		s := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(s, "SUCCESS") || strings.HasPrefix(s, "ERROR") {
			break
		}
		if rerr != nil {
			break
		}
	}
}

// ovpnStatusIPs parses an OpenVPN status-version 3 file and returns the set of
// virtual (tunnel) IPs currently held by connected clients.
func ovpnStatusIPs(statusPath string) map[string]bool {
	set := map[string]bool{}
	// OpenVPN rewrites this file IN PLACE every few seconds; a read that lands mid-
	// rewrite sees a truncated file (missing CLIENT_LIST rows). Under User Limit
	// "reject" that makes a live device look absent and wrongly admits an extra one.
	// A complete status ends with an "END" line — read a few times until we see one,
	// and union every read's rows so a partial snapshot can only ADD, never drop, a
	// device (a more-complete "used" set is always the safe direction).
	for attempt := 0; attempt < 8; attempt++ {
		data, err := os.ReadFile(statusPath)
		if err != nil {
			break
		}
		complete := false
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "END" {
				complete = true
			}
			// CLIENT_LIST<TAB>CommonName<TAB>RealAddr<TAB>VirtualAddr<TAB>...
			if !strings.HasPrefix(line, "CLIENT_LIST\t") {
				continue
			}
			f := strings.Split(line, "\t")
			if len(f) > 3 && f[3] != "" {
				set[f[3]] = true
			}
		}
		if complete {
			break // got a whole snapshot — trustworthy
		}
		time.Sleep(10 * time.Millisecond) // landed mid-rewrite; let it finish, retry
	}
	return set
}

// Usage: vpn-ui openvpn-connect {inbound_id}
// Reads common_name and ifconfig_pool_remote_ip from environment.
func openvpnConnect() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: vpn-ui openvpn-connect <inbound_id>")
		os.Exit(1)
	}

	inboundId, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid inbound_id:", err)
		os.Exit(1)
	}
	username := os.Getenv("common_name")
	ip := os.Getenv("ifconfig_pool_remote_ip")

	if username == "" || ip == "" {
		os.Exit(0) // Nothing to do
	}

	// User Limit K>=2: if the panel published a block for this account, lease a
	// free IP inside it and push it to this device (duplicate-cn lets K devices
	// share the CN). os.Args[3] is OpenVPN's writable per-session config file.
	leased, mask, reject := ovpnLeaseBlockIP(inboundId, username, ip, ovpnSessionKey())
	if reject {
		// User Limit reached with strategy=reject: a non-zero exit from a
		// client-connect script makes OpenVPN refuse this device.
		fmt.Fprintln(os.Stderr, "user limit reached; rejecting client")
		os.Exit(1)
	}
	if leased != "" {
		if len(os.Args) >= 4 && os.Args[3] != "" {
			_ = os.WriteFile(os.Args[3], []byte(fmt.Sprintf("ifconfig-push %s %s\n", leased, mask)), 0644)
		}
		ip = leased
	}

	secret := readRadiusSecret()
	if secret == "" {
		os.Exit(0)
	}

	sessionID := fmt.Sprintf("openvpn-%d-%s-%s", inboundId, username, ip)

	packet := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Start)
	rfc2866.AcctSessionID_SetString(packet, sessionID)
	rfc2865.UserName_SetString(packet, username)
	rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))
	rfc2865.FramedIPAddress_Set(packet, net.ParseIP(ip))

	resp, err := radius.Exchange(context.Background(), packet, "127.0.0.1:1813")
	if err != nil {
		fmt.Fprintf(os.Stderr, "RADIUS acct-start failed: %v\n", err)
		os.Exit(0)
	}
	if resp.Code != radius.CodeAccountingResponse {
		fmt.Fprintf(os.Stderr, "RADIUS acct-start unexpected code: %v\n", resp.Code)
	}
	os.Exit(0)
}

// openvpnDisconnect handles OpenVPN client-disconnect via RADIUS Acct-Stop.
// Usage: vpn-ui openvpn-disconnect {inbound_id}
// Reads common_name and ifconfig_pool_remote_ip from environment.
func openvpnDisconnect() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: vpn-ui openvpn-disconnect <inbound_id>")
		os.Exit(1)
	}

	inboundId, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid inbound_id:", err)
		os.Exit(1)
	}
	username := os.Getenv("common_name")
	ip := os.Getenv("ifconfig_pool_remote_ip")

	if username == "" || ip == "" {
		os.Exit(0)
	}

	// Free this device's block gap-lease immediately (leases are named by block IP,
	// keyed by the pool IP) so the slot reopens now instead of at the lease TTL, and
	// recover the leased block IP so this Acct-Stop's session-id matches the Acct-Start
	// the connect hook sent (which used the leased IP, not the pool IP).
	proto := "udp"
	if strings.HasPrefix(ip, "10.3.") {
		proto = "tcp"
	}
	dir := fmt.Sprintf("/etc/openvpn/server-%d", inboundId)
	leaseDir := filepath.Join(dir, "leases-"+proto)
	if leased := ovpnRemoveLeaseBySession(leaseDir, ovpnSessionKey()); leased != "" {
		// Tell the connect hook this address is free NOW; the status file will not say
		// so for up to another 5s, and a redial in between would be refused.
		ovpnWriteRelease(dir, proto, leased)
		ip = leased
	}

	secret := readRadiusSecret()
	if secret == "" {
		os.Exit(0)
	}

	sessionID := fmt.Sprintf("openvpn-%d-%s-%s", inboundId, username, ip)

	// Read session duration from env (OpenVPN provides time_duration in seconds)
	var sessionTime uint32
	if dur := os.Getenv("time_duration"); dur != "" {
		if d, err := strconv.ParseUint(dur, 10, 32); err == nil {
			sessionTime = uint32(d)
		}
	}

	packet := radius.New(radius.CodeAccountingRequest, []byte(secret))
	rfc2866.AcctStatusType_Set(packet, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctSessionID_SetString(packet, sessionID)
	rfc2865.UserName_SetString(packet, username)
	rfc2865.NASIdentifier_SetString(packet, fmt.Sprintf("openvpn-%d", inboundId))
	rfc2865.FramedIPAddress_Set(packet, net.ParseIP(ip))
	if sessionTime > 0 {
		rfc2866.AcctSessionTime_Set(packet, rfc2866.AcctSessionTime(sessionTime))
	}

	radius.Exchange(context.Background(), packet, "127.0.0.1:1813")
	os.Exit(0)
}

// main is the entry point of the pro-ui application.
// It parses command-line arguments to run the web server, migrate database, or update settings.
func main() {
	if len(os.Args) < 2 {
		runWebServer()
		return
	}

	// Root is required for every mode except the harmless info switches (version /
	// help): the panel and all its subcommands bind privileged ports, write /etc +
	// systemd units, and manage nftables/routing/daemons. Enforce it up front so a
	// non-root invocation fails with one clear message instead of an obscure
	// permission error deeper in.
	if !isInfoArg(os.Args[1]) {
		requireRoot()
	}

	// Standalone maintenance switches. They can be combined in any order, e.g.
	//   vpn-ui --random --systemd
	//   vpn-ui --user admin --pass s3cret --port 8443 --path panel --systemd
	// and are handled before flag parsing (they aren't top-level flags). Bare
	// switches accept a `--` or bare form; the value switches take the next arg (or
	// the `--key=value` form):
	//   --random / random     randomize port + username + password + web path
	//   --user <name>         set the panel login username
	//   --pass <password>     set the panel login password
	//   --port <n>            set the panel web port
	//   --path <basePath>     set the panel web base path
	//   --systemd / systemd    install + enable-at-boot + start as a systemd unit
	//   --cores <keep|remove>  with --uninstall only: pre-answer whether the
	//                          installed VPN cores are removed with the panel
	// The value switches are "work safe" exactly like --random: stop the running
	// unit, write the change, start it again. --random and the explicit values run
	// before --systemd, so a combined invocation boots the unit with the new
	// settings.
	{
		doRandom, doSystemd, doUninstall, doForce, onlySwitches := false, false, false, false, true
		var setUser, setPass, setPath string
		var setPort int
		// Kept out of hasExplicit on purpose: that flag drives applyExplicitSetting
		// (panel port/user/pass/path), which the uninstall path never reaches.
		var setCores string
		hasExplicit := false
		cliArgs := os.Args[1:]
		for i := 0; i < len(cliArgs); i++ {
			key := strings.TrimPrefix(cliArgs[i], "--")
			// Support `--key=value` in addition to `--key value`.
			inlineVal, hasInline := "", false
			if eq := strings.IndexByte(key, '='); eq >= 0 {
				inlineVal, key, hasInline = key[eq+1:], key[:eq], true
			}
			takeVal := func() string {
				if hasInline {
					return inlineVal
				}
				if i+1 < len(cliArgs) {
					i++
					return cliArgs[i]
				}
				return ""
			}
			switch key {
			case "random":
				doRandom = true
			case "systemd":
				doSystemd = true
			case "uninstall":
				doUninstall = true
			case "yes", "force":
				doForce = true
			case "cores":
				// Pre-answers the uninstall's cores question. "remove" is the word the
				// switch documents; "delete" is accepted because it is the spelling
				// service.InboundsDelete uses, and the two vocabularies must not drift.
				switch v := strings.ToLower(strings.TrimSpace(takeVal())); v {
				case "keep":
					setCores = service.InboundsKeep
				case "remove", "delete":
					setCores = service.InboundsDelete
				default:
					// Refuse rather than fall back to a default: a typo'd answer under
					// --yes would otherwise remove the very cores it was meant to keep.
					fmt.Fprintf(os.Stderr, "invalid --cores value %q (want 'keep' or 'remove')\n", v)
					os.Exit(1)
				}
			case "user":
				setUser, hasExplicit = takeVal(), true
			case "pass":
				setPass, hasExplicit = takeVal(), true
			case "path":
				setPath, hasExplicit = takeVal(), true
			case "port":
				if p, err := strconv.Atoi(strings.TrimSpace(takeVal())); err == nil {
					setPort = p
				}
				hasExplicit = true
			default:
				onlySwitches = false
			}
		}
		if onlySwitches && (doRandom || doSystemd || doUninstall || hasExplicit) {
			requireRoot()
			// Uninstall is exclusive and destructive — if requested, run only it.
			if doUninstall {
				runUninstall(doForce, setCores)
				return
			}
			if doRandom {
				randomizeSetting()
			}
			// Explicit --user/--pass/--port/--path apply after --random (an explicit
			// value wins over the random one) and before --systemd (so the unit boots
			// with the new settings).
			if hasExplicit {
				applyExplicitSetting(setUser, setPass, setPort, setPath)
			}
			if doSystemd {
				installSystemd()
			}
			return
		}
	}

	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "show version")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)

	settingCmd := flag.NewFlagSet("setting", flag.ExitOnError)
	var port int
	var username string
	var password string
	var webBasePath string
	var listenIP string
	var getListen bool
	var webCertFile string
	var webKeyFile string
	var subCertFile string
	var subKeyFile string
	var tgbottoken string
	var tgbotchatid string
	var enabletgbot bool
	var tgbotRuntime string
	var reset bool
	var show bool
	var getCert bool
	var selfSignCert bool
	var resetTwoFactor bool
	settingCmd.BoolVar(&reset, "reset", false, "Reset all settings")
	settingCmd.BoolVar(&show, "show", false, "Display current settings")
	settingCmd.IntVar(&port, "port", 0, "Set panel port number")
	settingCmd.StringVar(&username, "username", "", "Set login username")
	settingCmd.StringVar(&password, "password", "", "Set login password")
	settingCmd.StringVar(&webBasePath, "webBasePath", "", "Set base path for Panel")
	settingCmd.StringVar(&listenIP, "listenIP", "", "set panel listenIP IP")
	settingCmd.BoolVar(&resetTwoFactor, "resetTwoFactor", false, "Reset two-factor authentication settings")
	settingCmd.BoolVar(&getListen, "getListen", false, "Display current panel listenIP IP")
	settingCmd.BoolVar(&getCert, "getCert", false, "Display current certificate settings")
	settingCmd.StringVar(&webCertFile, "webCert", "", "Set path to public key file for panel")
	settingCmd.StringVar(&webKeyFile, "webCertKey", "", "Set path to private key file for panel")
	// The subscription server's own pair. Separate flags because it is a separate
	// listener with separate settings, and because -webCert moving it as well is
	// exactly the behaviour that had to go.
	settingCmd.StringVar(&subCertFile, "subCert", "", "Set path to public key file for the subscription server (unset leaves it alone)")
	settingCmd.StringVar(&subKeyFile, "subCertKey", "", "Set path to private key file for the subscription server")
	settingCmd.BoolVar(&selfSignCert, "selfsign", false, "Generate a self-signed TLS cert for the panel and enable HTTPS")
	settingCmd.StringVar(&tgbottoken, "tgbottoken", "", "Set token for Telegram bot")
	settingCmd.StringVar(&tgbotRuntime, "tgbotRuntime", "", "Set cron time for Telegram bot notifications")
	settingCmd.StringVar(&tgbotchatid, "tgbotchatid", "", "Set chat ID for Telegram bot notifications")
	settingCmd.BoolVar(&enabletgbot, "enabletgbot", false, "Enable notifications via Telegram bot")

	oldUsage := flag.Usage
	flag.Usage = func() {
		oldUsage()
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("    run            run web panel")
		fmt.Println("    migrate        migrate form other/old vpn-ui")
		fmt.Println("    import         import a 3x-ui/vpn-ui backup DB over the current one")
		fmt.Println("                   (--from <path>; keeps this panel's port/path/cert/secret)")
		fmt.Println("    setting        set settings")
		fmt.Println("    cert           set the PANEL's TLS certificate:")
		fmt.Println("                   -webCert <cert> -webCertKey <key>")
		fmt.Println("                   (-selfsign generates one, -reset clears it)")
		fmt.Println("                   the subscription server keeps its own and is left")
		fmt.Println("                   alone; point it at a pair with:")
		fmt.Println("                   -subCert <cert> -subCertKey <key>")
		fmt.Println("    info           show the panel login, access URL and service state")
		fmt.Println("                   (--json for scripts, --get <field> for one raw value)")
		fmt.Println("    ctl <cmd>      control the RUNNING panel over its socket:")
		fmt.Println("                   " + strings.Join(service.ControlCommands, ", "))
		fmt.Println("    update         install the latest release (backs the DB up first)")
		fmt.Println("    install-menu   install the 'vpn-ui' management menu to " + service.MenuScriptPath)
		fmt.Println("    --systemd      install+enable+start the panel as a systemd service")
		fmt.Println("    --random       randomize panel port + username + password + web path")
		fmt.Println("                   (combinable, e.g. --random --systemd)")
		fmt.Println("    --user <name>  set panel login username")
		fmt.Println("    --pass <pw>    set panel login password")
		fmt.Println("    --port <n>     set panel web port")
		fmt.Println("    --path <p>     set panel web base path")
		fmt.Println("                   work-safe like --random (stops the unit, applies,")
		fmt.Println("                   restarts it); combinable with --systemd, e.g.")
		fmt.Println("                   --user u --pass p --port 8443 --path panel --systemd")
		fmt.Println("    revert-accounts")
		fmt.Println("                   drop the accounts layer and go back to the legacy")
		fmt.Println("                   one-client-per-inbound model (refuses while any")
		fmt.Println("                   account is on more than one inbound)")
		fmt.Println("    --uninstall    remove the panel: systemd unit, daemons, firewall,")
		fmt.Println("                   routing, /etc configs, bundles, logs, DB and the binary")
		fmt.Println("                   (--yes to skip the confirmation prompt)")
		fmt.Println("    --cores keep|remove")
		fmt.Println("                   with --uninstall: pre-answer whether the installed VPN")
		fmt.Println("                   cores go too. Unset asks (Enter keeps them); with --yes")
		fmt.Println("                   and no --cores they are removed, as they always were")
	}

	flag.Parse()
	if showVersion {
		fmt.Println(config.GetVersion())
		return
	}

	switch os.Args[1] {
	case "run":
		err := runCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		runWebServer()
	case "migrate":
		migrateDb()
	case "revert-accounts":
		revertAccounts()
	case "import":
		importDb()
	case "setting":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		if reset {
			if err = resetSetting(); err != nil {
				return
			}
		} else {
			if err = updateSetting(port, username, password, webBasePath, listenIP, resetTwoFactor); err != nil {
				return
			}
		}
		if show {
			showSetting(show)
		}
		if getListen {
			GetListenIP(getListen)
		}
		if getCert {
			GetCertificate(getCert)
		}
		if (tgbottoken != "") || (tgbotchatid != "") || (tgbotRuntime != "") {
			updateTgbotSetting(tgbottoken, tgbotchatid, tgbotRuntime)
		}
		if enabletgbot {
			updateTgbotEnableSts(enabletgbot)
		}
	case "cert":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		// WHICH FLAGS WERE TYPED, not which ones ended up with a value. Visit walks
		// only the flags actually present on the command line, and that distinction
		// is load-bearing twice over: it separates `-subCert ""` (clear the
		// subscription listener) from an absent -subCert (leave it alone), and
		// without it `vpn-ui cert -subCert c -subCertKey k` would fall through to
		// updateCert("", "") and CLEAR the panel's certificate as a side effect of
		// setting the subscription server's, which is this bug wearing the other hat.
		typed := map[string]bool{}
		settingCmd.Visit(func(f *flag.Flag) { typed[f.Name] = true })
		movePanel, moveSub := certCommandTargets(typed)

		switch {
		case reset:
			updateCert("", "")
		case selfSignCert:
			generateSelfSignedPanelCert()
		default:
			if moveSub {
				updateSubCert(subCertFile, subKeyFile)
			}
			if movePanel {
				updateCert(webCertFile, webKeyFile)
			}
		}
	case "info":
		if err := runInfo(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "ctl":
		if err := runCtl(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "update":
		if err := runUpdate(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "install-menu":
		installMenuScript(os.Args[2:])
	case "install-acme":
		installAcmeScript(os.Args[2:])
	case "acme-deps":
		fmt.Println(service.EnsureAcmeDeps())
	case "cf":
		if err := runCloudflare(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "openvpn-auth":
		openvpnAuth()
	case "openvpn-connect":
		openvpnConnect()
	case "openvpn-disconnect":
		openvpnDisconnect()
	case "openvpn-evict":
		openvpnEvict()
	case "help":
		flag.Usage()
	default:
		fmt.Println("Invalid subcommands")
		fmt.Println()
		// Show the full top-level command list (incl. --user/--pass/--port/--path)
		// on a bad command, not just the run/setting sub-flag usages.
		flag.Usage()
		fmt.Println()
		runCmd.Usage()
		fmt.Println()
		settingCmd.Usage()
	}
}
