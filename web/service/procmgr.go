package service

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/logger"
)

// daemonBin resolves a bundled daemon (preferred) or a host binary from PATH.
func daemonBin(name string) string {
	if p := backend.DaemonPath(name); p != "" {
		return p
	}
	// accel-ppp (SSTP) ships as a relocatable bundle TREE rooted at a fixed path,
	// not a flat BinDir binary, so its launchers (accel-pppd/accel-cmd) resolve
	// here rather than via DaemonPath.
	if p := backend.AccelBinPath(name); p != "" {
		return p
	}
	// strongSwan (IKEv2) also ships as a relocatable bundle TREE, so charon/swanctl/pki
	// resolve to their launcher wrappers here rather than via DaemonPath.
	if p := backend.StrongswanBinPath(name); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return name
}

// pppdEnv returns the environment a pppd-based daemon (xl2tpd/pptpd) needs so
// OpenSSL finds the bundled legacy provider for MS-CHAP/MPPE. Empty for a system
// pppd (whose OpenSSL providers differ and must not be overridden).
func pppdEnv() []string {
	if backend.UsingBundledPppd() {
		return []string{"OPENSSL_MODULES=" + backend.OpenSSLModules}
	}
	return nil
}

// pptpdArgs returns pptpd's launch args: foreground, plus the bundled pppd when
// the bundle is in use.
func pptpdArgs() []string {
	args := []string{"--fg"}
	if backend.UsingBundledPppd() {
		args = append(args, "--ppp", backend.PppdBundled)
	}
	return args
}

// linkPptpCtrl ensures pptpd can exec the bundled pptpctrl from its compiled
// path. Previously done while writing the systemd unit; still required now that
// pptpd runs as a child process.
func linkPptpCtrl() {
	if err := backend.LinkPptpCtrl(); err != nil {
		logger.Warning("PPTP: failed to link pptpctrl:", err)
	}
}

// procmgr supervises the bundled VPN daemons (openvpn, xl2tpd, pptpd) as child
// processes of the panel binary instead of systemd services. Each managed
// process:
//   - captures stdout+stderr into a bounded ring buffer for the "Logs" viewer,
//   - is auto-restarted if it exits unexpectedly (mirrors systemd Restart=on-failure),
//   - dies with the panel (StopAll on shutdown), and its whole process group is
//     signalled so pppd children spawned by xl2tpd/pptpd are reaped too.

const procLogMaxLines = 800

// procLog is a bounded in-memory ring buffer of a daemon's recent output.
type procLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *procLog) Write(p []byte) (int, error) {
	// Stamp each captured line so the Logs viewer shows when output arrived
	// (daemon stdout/stderr has no timestamp of its own). Matches the panel
	// logger's time format for consistency across cores.
	ts := time.Now().Format("2006/01/02 15:04:05")
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, ln := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if ln == "" {
			continue
		}
		l.lines = append(l.lines, ts+" "+ln)
	}
	if over := len(l.lines) - procLogMaxLines; over > 0 {
		l.lines = l.lines[over:]
	}
	return len(p), nil
}

func (l *procLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *procLog) add(line string) { _, _ = l.Write([]byte(line + "\n")) }

// managedProc is one supervised child daemon.
type managedProc struct {
	name string
	log  *procLog

	mu      sync.Mutex
	bin     string
	args    []string
	env     []string
	dir     string
	cmd     *exec.Cmd
	stopped bool // Stop() called → suppress auto-restart
	gen     int  // bumped on every (re)start/stop; supervisors compare against it
}

// ProcManager supervises the bundled VPN daemons as child processes.
type ProcManager struct {
	mu    sync.Mutex
	procs map[string]*managedProc
}

var procMgr = &ProcManager{procs: map[string]*managedProc{}}

// GetProcManager returns the shared process manager.
func GetProcManager() *ProcManager { return procMgr }

func (m *ProcManager) get(name string) *managedProc {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.procs[name]
}

// Start (re)launches the named daemon with the given command, replacing any
// running instance. Output is captured to the daemon's log ring buffer.
func (m *ProcManager) Start(name, bin string, args, env []string, dir string) error {
	m.mu.Lock()
	p := m.procs[name]
	if p == nil {
		p = &managedProc{name: name, log: &procLog{}}
		m.procs[name] = p
	}
	m.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	// Supersede any current instance/supervisor and stop it.
	p.gen++
	old := p.cmd
	p.terminateLocked()
	// Wait for the old instance to actually exit before launching the replacement.
	// terminateLocked only *signals* it; relaunching immediately races the dying
	// process for its listening port. Single-port daemons (ocserv binds one TCP+UDP
	// port) then fail the new instance with "bind: Address in use" → exit 1 → a 5s
	// procmgr restart window during which every client connection is refused.
	if old != nil && old.Process != nil {
		waitProcessExit(old.Process.Pid)
	}
	p.bin, p.args, p.env, p.dir = bin, args, env, dir
	p.stopped = false
	return p.launchLocked()
}

// waitProcessExit blocks until pid has exited — and thus released its ports —
// escalating a graceful SIGTERM to SIGKILL if ignored. Bounded (~3s) so a wedged
// process can't stall a restart forever. The old instance's supervisor reaps it
// via cmd.Wait() concurrently (outside p.mu), so Kill(pid,0) flips to ESRCH once
// it's gone.
func waitProcessExit(pid int) {
	for i := 0; i < 60; i++ { // up to ~3s (60 × 50ms)
		if err := syscall.Kill(pid, 0); err == syscall.ESRCH {
			return
		}
		if i == 20 { // ~1s in and still alive → force it
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// launchLocked spawns the process and its supervisor goroutine (p.mu held).
func (p *managedProc) launchLocked() error {
	cmd := exec.Command(p.bin, p.args...)
	cmd.Dir = p.dir
	if len(p.env) > 0 {
		cmd.Env = append(os.Environ(), p.env...)
	}
	cmd.Stdout = p.log
	cmd.Stderr = p.log
	// Own process group so we can signal pppd/helper children too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		p.log.add("[procmgr] failed to start " + p.bin + ": " + err.Error())
		return err
	}
	p.cmd = cmd
	p.log.add("[procmgr] started: " + p.bin + " " + strings.Join(p.args, " "))
	gen := p.gen
	go p.supervise(cmd, gen)
	return nil
}

// supervise waits for the process; if it exits without an explicit Stop and is
// still the current generation, it is restarted after a short delay.
func (p *managedProc) supervise(cmd *exec.Cmd, gen int) {
	waitErr := cmd.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != p.gen || p.stopped {
		return // superseded or intentionally stopped
	}
	msg := "exited cleanly"
	if waitErr != nil {
		msg = "exited: " + waitErr.Error()
	}
	logger.Warningf("procmgr: %s %s — restarting in 5s", p.name, msg)
	p.log.add("[procmgr] " + msg + " — restarting in 5s")
	restartGen := p.gen
	go func() {
		time.Sleep(5 * time.Second)
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.stopped || p.gen != restartGen {
			return
		}
		p.gen++
		// Reap the crashed process's orphaned group (e.g. xl2tpd/pptpd's pppd children,
		// which survive the parent's death and would otherwise wedge a fresh daemon —
		// the "says running but not working" state that only a manual restart cleared).
		// Start() does this before every launch; the auto-restart must too.
		p.terminateLocked()
		_ = p.launchLocked()
	}()
}

// terminateLocked signals the current process group with SIGTERM (p.mu held).
func (p *managedProc) terminateLocked() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	pid := p.cmd.Process.Pid
	// Negative pid → whole process group (reaps pppd children). Fall back to the
	// bare process if the group signal fails.
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
}

// Stop terminates the named daemon and disables auto-restart.
//
// It WAITS for the process to actually go, escalating to SIGKILL, rather than
// signalling and returning. terminateLocked only sends SIGTERM, and a daemon that is
// mid-retry can sit on it: a pppd dialling with `persist` outlived Stop by twelve
// minutes on a failed SSTP dial, respawning its pty child the whole time and taking
// its netdev up and down, while the driver's Down had already deleted every file it
// wrote. Nothing was left holding a reference to it, so only a kill -9 by hand or a
// reboot cleared it.
//
// Bounded at ~3s by waitProcessExit, which is the same escalation Start already
// performs before relaunching, so a wedged daemon cannot stall a teardown either.
func (m *ProcManager) Stop(name string) error {
	p := m.get(name)
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	p.gen++
	var pid int
	if p.cmd != nil && p.cmd.Process != nil {
		pid = p.cmd.Process.Pid
	}
	p.terminateLocked()
	if pid > 0 {
		waitProcessExit(pid)
	}
	return nil
}

// StopByPrefix stops every managed daemon whose name starts with prefix
// (e.g. "openvpn-server-" for all OpenVPN instances).
func (m *ProcManager) StopByPrefix(prefix string) {
	for _, name := range m.namesWithPrefix(prefix) {
		_ = m.Stop(name)
	}
}

func (m *ProcManager) namesWithPrefix(prefix string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for n := range m.procs {
		if strings.HasPrefix(n, prefix) {
			names = append(names, n)
		}
	}
	return names
}

// IsRunning reports whether the named daemon is currently up.
func (m *ProcManager) IsRunning(name string) bool {
	p := m.get(name)
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.stopped && p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

// AnyRunningWithPrefix reports whether any managed daemon with the given name
// prefix is up (e.g. any OpenVPN transport for an inbound).
func (m *ProcManager) AnyRunningWithPrefix(prefix string) bool {
	for _, n := range m.namesWithPrefix(prefix) {
		if m.IsRunning(n) {
			return true
		}
	}
	return false
}

// Logs returns the captured output of the named daemon (most recent lines).
func (m *ProcManager) Logs(name string) string {
	p := m.get(name)
	if p == nil {
		return ""
	}
	return p.log.String()
}

// LogsByPrefix concatenates the logs of all daemons matching the prefix, each
// section headed by its name. Used for cores that run several processes
// (OpenVPN: one per inbound/transport).
func (m *ProcManager) LogsByPrefix(prefix string) string {
	names := m.namesWithPrefix(prefix)
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("===== " + n + " =====\n")
		b.WriteString(m.Logs(n))
		b.WriteString("\n")
	}
	return b.String()
}

// alive reports whether the named process is actually still running (ignoring
// the stopped flag).
func (m *ProcManager) alive(name string) bool {
	p := m.get(name)
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

// kill SIGKILLs the named process group (last resort for a straggler).
func (m *ProcManager) kill(name string) {
	p := m.get(name)
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil {
		pid := p.cmd.Process.Pid
		if syscall.Kill(-pid, syscall.SIGKILL) != nil {
			_ = p.cmd.Process.Kill()
		}
	}
}

// StopAll terminates every managed daemon and waits for them to exit (panel
// shutdown). Daemons that don't exit within the grace period are SIGKILLed, so
// nothing is left holding a port for the next panel start.
func (m *ProcManager) StopAll() {
	m.mu.Lock()
	names := make([]string, 0, len(m.procs))
	for n := range m.procs {
		names = append(names, n)
	}
	m.mu.Unlock()

	for _, n := range names {
		_ = m.Stop(n) // SIGTERM
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		anyAlive := false
		for _, n := range names {
			if m.alive(n) {
				anyAlive = true
				break
			}
		}
		if !anyAlive {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	for _, n := range names {
		if m.alive(n) {
			m.kill(n)
		}
	}
}

// migrateFromSystemdOnce tears down the previous systemd-based design (bundled
// units + running instances) so the panel can own the daemons as child
// processes. Idempotent and safe to call every startup: once the units are gone
// it is a no-op.
var migrateOnce sync.Once

func migrateFromSystemd() {
	migrateOnce.Do(func() {
		if !commandExists("systemctl") {
			return
		}
		// Stop + disable OpenVPN per-inbound instances.
		out, _ := exec.Command("systemctl", "list-units", "--all", "--no-legend", "openvpn-server@*").Output()
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimLeft(line, "●* "))
			if len(fields) > 0 && strings.HasPrefix(fields[0], "openvpn-server@") {
				_ = exec.Command("systemctl", "disable", "--now", fields[0]).Run()
			}
		}
		// Stop + disable the single-instance daemons.
		for _, unit := range []string{"xl2tpd", "pptpd"} {
			_ = exec.Command("systemctl", "disable", "--now", unit).Run()
		}
		// When we run our own bundled pluto, the host ipsec.service must not also be
		// running — it would hold UDP 500/4500 and conflict with the bundled daemon.
		if usingBundledIpsec() {
			_ = exec.Command("systemctl", "disable", "--now", "ipsec").Run()
		}
		// Remove the unit files the old design generated.
		for _, f := range []string{
			"/etc/systemd/system/openvpn-server@.service",
			"/etc/systemd/system/xl2tpd.service",
			"/etc/systemd/system/pptpd.service",
		} {
			_ = os.Remove(f)
		}
		_ = exec.Command("systemctl", "daemon-reload").Run()
		logger.Info("procmgr: migrated VPN daemons off systemd (now child processes)")

		// Kill orphaned bundled daemons left by a previous panel that was killed
		// without a clean shutdown (SIGKILL/crash) — they would hold the ports the
		// child processes need. Safe: procMgr has spawned nothing yet at this
		// point, so only pre-existing processes match.
		if commandExists("pkill") {
			// accel-pppd (SSTP) runs through the bundle's musl loader-wrapper, so its
			// cmdline contains ".../sbin/accel-pppd.bin"; a `-f` match on the resolved
			// launcher path (".../sbin/accel-pppd") is a substring of that and reaps a
			// stale orphan from a crashed panel. accel-pppd does NOT retitle itself
			// (unlike ocserv), so it does not need the exact-name `-x` pass below.
			for _, d := range []string{"openvpn", "xl2tpd", "pptpd", "accel-pppd"} {
				bin := daemonBin(d)
				if bin == d {
					continue // unresolved — avoid a too-broad match on a bare name
				}
				_ = exec.Command("pkill", "-KILL", "-f", bin).Run()
			}
			// Orphaned bundled pluto from a crashed panel (holds UDP 500/4500).
			if usingBundledIpsec() {
				_ = exec.Command("pkill", "-KILL", "-f", backend.LibreswanBundleRoot+"/libexec/ipsec/pluto.bin").Run()
			}
			// Orphaned bundled charon (IKEv2) from a crashed panel — it also holds UDP
			// 500/4500. charon runs via the musl loader wrapper, so its cmdline contains
			// the absolute charon.bin path; match on that (the sbin/charon wrapper is in a
			// different dir than libexec/ipsec/charon.bin, so a launcher-path -f match
			// like accel-pppd's would miss it).
			if backend.HasStrongswanBundle() {
				_ = exec.Command("pkill", "-KILL", "-f", backend.StrongswanBundleRoot+"/libexec/ipsec/charon.bin").Run()
			}
			// Orphaned ocserv from a crashed/killed previous panel. ocserv RENAMES its
			// processes to ocserv-main/-sm/-worker, so `pkill -f <exec path>` (used
			// above) can never match them — their cmdline is the retitled name, not
			// the binary path. Kill by EXACT process name instead (-x). Without this
			// the orphan keeps holding the ocserv TCP/UDP port, so the panel's fresh
			// ocserv can't bind → exit 1 → a permanent 5s procmgr restart loop, while
			// the orphan keeps old sessions alive that the panel can't manage (occtl
			// eviction hits the panel's socket, not the orphan) — exactly the
			// "User Limit does nothing / new client has no internet" failure. Safe
			// here: procMgr has spawned nothing yet, so any ocserv* is a stale orphan.
			for _, comm := range []string{"ocserv-main", "ocserv-sm", "ocserv-worker", "ocserv"} {
				_ = exec.Command("pkill", "-KILL", "-x", comm).Run()
			}
		}
	})
}
