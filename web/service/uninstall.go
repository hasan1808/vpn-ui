package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"
)

// MenuScriptPath is where the `vpn-ui` management menu is installed, by
// `vpn-ui-amd64 install-menu` (which deploy.sh runs on every install and update).
// Declared here, in the package that must REMOVE it, so the installer in main.go
// and this teardown can never drift apart on the path.
const MenuScriptPath = "/usr/bin/vpn-ui"

// UninstallOptions configures a host teardown.
type UninstallOptions struct {
	// ExePath is the running panel binary, used to kill any *other* panel
	// instance and to resolve a relative bin/ dir against the binary's directory.
	ExePath string
}

// UninstallReport records the outcome of a best-effort teardown: what was
// removed, what was deliberately kept (and must be removed by hand), and any
// errors encountered along the way (teardown never aborts on a single failure).
type UninstallReport struct {
	Removed []string
	Kept    []string
	Errors  []string
}

func (r *UninstallReport) fail(what string, err error) {
	r.Errors = append(r.Errors, fmt.Sprintf("%s: %v", what, err))
}

// Uninstall reverses everything the panel installs on the host. It is the
// inverse of provisioning + `--systemd`, ordered processes/services → firewall
// → routing → files so nothing is in use when its backing files are removed. The
// database and the binary itself are left to the caller (main.runUninstall).
//
// Distro packages (libreswan, nftables, iproute2, kernel modules) and the
// irreversible boot-default / modprobe-blacklist edits are intentionally kept
// and reported for the operator. Must run as root.
func Uninstall(opts UninstallOptions) *UninstallReport {
	r := &UninstallReport{}
	logger.Info("uninstall: starting host teardown")

	// 1. The panel's own systemd unit (default "vpn-ui"). disable --now stops it
	//    without self-killing: this process was started outside that unit's PID.
	var sd SystemdService
	name := sd.GetServiceName()
	if err := sd.RemoveService(name); err != nil {
		r.fail("remove systemd unit "+name, err)
	} else {
		r.Removed = append(r.Removed, unitPath(name))
	}

	// 1b. The `vpn-ui` management menu. Unlinking it while it is the very script
	//     running this uninstall is safe on Linux: bash holds an open fd on it, so
	//     the inode outlives the directory entry (same reason main.runUninstall can
	//     remove the running binary).
	removePath(r, MenuScriptPath)
	// The panel's control socket, now that step 1 stopped the panel that served it.
	// A leftover socket file is what StartControlSocket's stale-socket check exists
	// to clear, but an uninstall should not leave one behind at all.
	removePath(r, ControlSocketPath())

	// 2. Stop/kill the daemons a live panel supervised (our fresh process's
	//    procMgr is empty, so fall back to pkill by resolved binary path).
	stopVpnDaemons(r, opts.ExePath)

	// 2b. Client-side VPN outbound tunnels (wg/gre/tun/ppp/xfrm netdevs plus whatever
	//     client each driver spawned). Nothing else here reaches them: they are not
	//     procMgr children of THIS process, they are not in the /etc list below, and
	//     the panel that raised them was SIGKILLed just above, which skips the shutdown
	//     hook that would normally take them down. Left alone, an uninstalled host
	//     keeps a live interface with a route into somebody else's VPN.
	//
	//     Runs after stopVpnDaemons on purpose: with every other panel dead, nothing is
	//     left to reconcile a tunnel back up behind us. Driven off the stored list and
	//     each driver's own Down rather than a name pattern, so a protocol added later
	//     is covered on the day its driver lands.
	var vpnOut VpnOutboundService
	if tunnels := vpnOut.List(); len(tunnels) > 0 {
		vpnOut.StopAll()
		for _, t := range tunnels {
			r.Removed = append(r.Removed, "vpn outbound tunnel "+t.Tag+" ("+t.Kind+")")
		}
	}

	// 3. Host ipsec.service (only present on the non-bundled libreswan path).
	if commandExists("systemctl") {
		_, _ = systemctl("disable", "--now", "ipsec")
	}

	// 4. Cloudflare warp-cli (SOCKS5), via its own bundled uninstaller.
	uninstallWarpSocks(r)

	// 5. Legacy per-daemon systemd units (superseded by the child-process design;
	//    removed defensively in case an old install left them behind).
	for _, u := range []string{"xl2tpd", "openvpn-server@", "pptpd"} {
		p := unitPath(u)
		if _, err := os.Lstat(p); err == nil {
			if commandExists("systemctl") {
				_, _ = systemctl("disable", "--now", u)
			}
			removePath(r, p)
		}
	}
	if commandExists("systemctl") {
		_, _ = systemctl("daemon-reload")
	}

	// 6. nftables table + legacy iptables chains + firewalld trust.
	if commandExists("nft") {
		_ = exec.Command("nft", "delete", "table", "ip", "vpn").Run()
	}
	(&NftService{}).CleanupLegacyIptables()
	if firewalldRunning() {
		_ = exec.Command("firewall-cmd", "--zone=trusted", "--remove-source="+vpnAddrSpace).Run()
		_ = exec.Command("firewall-cmd", "--permanent", "--zone=trusted", "--remove-source="+vpnAddrSpace).Run()
	}

	// 7. Policy routing (fwmark 1 → table 100). Not reversed anywhere else.
	if commandExists("ip") {
		// There may be more than one identical rule; delete until none remain.
		for i := 0; i < 10; i++ {
			if err := exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", "100").Run(); err != nil {
				break
			}
		}
		_ = exec.Command("ip", "route", "flush", "table", "100").Run()
	}

	// 8. /etc configs, runtime dirs, seq files, logs.
	for _, p := range []string{
		"/etc/vpn-ui", // nft config dir (vpn.nft)
		"/etc/xl2tpd/xl2tpd.conf",
		"/etc/ppp/options.xl2tpd",
		"/etc/ipsec.conf",
		"/etc/ipsec.secrets",
		"/etc/pptpd.conf",
		"/etc/ppp/pptpd-options",
		"/etc/ppp/radius", // panel-owned subdir of the host /etc/ppp
		"/etc/swanctl/conf.d/l2tp.conf",
		"/etc/modules-load.d/vpn-ui.conf",
		"/etc/sysctl.d/99-vpn-ui.conf",
	} {
		removePath(r, p)
	}
	// Per-inbound OpenVPN config dirs (/etc/openvpn/server-<id>).
	if matches, _ := filepath.Glob("/etc/openvpn/server-*"); len(matches) > 0 {
		for _, m := range matches {
			removePath(r, m)
		}
	}
	for _, p := range []string{"/var/run/xl2tpd", "/var/run/openvpn", "/run/pluto"} {
		removePath(r, p)
	}
	if matches, _ := filepath.Glob("/var/run/radius-*.seq"); len(matches) > 0 {
		for _, m := range matches {
			removePath(r, m)
		}
	}
	removePath(r, config.GetLogFolder()) // /var/log/vpn-ui
	removePath(r, "/var/log/pluto.log")

	// 9. Bundled daemon trees + their host symlinks. Remove the outward symlinks
	//    ONLY when they point into our bundle, so a distro-native pppd is never
	//    unlinked; then remove the bundle root itself (pptpctrl link lives inside).
	removeSymlinkIfTarget(r, backend.PppdSystem, backend.PppdBundled)
	removeSymlinkIfTarget(r, backend.PppdPluginDir, backend.PppdBundleRoot+"/lib/pppd")
	removePath(r, backend.PppdBundleRoot) // /usr/libexec/vpn-ui (incl. libreswan/, pptpctrl)
	if usingBundledIpsec() {
		removePath(r, backend.LibreswanNssDir) // /etc/ipsec.d — only ours on the bundled path
	}

	// 9b. Everything the CORE CATALOG owns, driven off the catalog rather than a
	//     hand-written list.
	//
	//     The hand-written steps above are frozen at the four-protocol era: they
	//     name xl2tpd, pptpd, openvpn and libreswan and nothing else. Six cores
	//     shipped after that (openconnect, sstp, ikev2, wgc, awg, mtproto, ssh),
	//     each declaring its own paths/globs/feats in coreCatalog, and none of it
	//     reached here — a verified uninstall on Ubuntu 24.04 left /etc/ocserv,
	//     /etc/vpn-ui-ikev2, /etc/strongswan.conf, /var/run/{ocserv,charon.vici}
	//     and both bundle trees behind. Iterating the catalog means core #11 is
	//     covered the day it is added, with no second list to remember.
	//
	//     Features are removed unconditionally here, unlike the per-core path
	//     which reference-counts them against the cores that REMAIN: this is a
	//     full uninstall, so nothing remains to keep them for.
	for _, spec := range coreCatalog {
		if spec.builtin {
			continue
		}
		for _, p := range spec.paths {
			removePath(r, p)
		}
		for _, g := range spec.globs {
			matches, err := filepath.Glob(g)
			if err != nil {
				continue
			}
			for _, m := range matches {
				removePath(r, m)
			}
		}
	}
	seenFeat := map[string]bool{}
	for _, spec := range coreCatalog {
		for _, f := range spec.feats {
			// featPppd/featPptpCtrl are already handled above, and featKernelMods
			// is deliberately a no-op (the host's kernel package is not ours).
			if seenFeat[f] || f == featPppd || f == featPptpCtrl || f == featKernelMods {
				continue
			}
			seenFeat[f] = true
			if step := removeFeature(f); step.Msg != "" {
				r.Removed = append(r.Removed, step.Name+": "+step.Msg)
			}
		}
	}

	// 10. The bin/ dir next to the binary (xray core, geo files, config.json, and
	//     the flat VPN daemons — all extract here now). Resolve a relative path
	//     against the exe's dir so it works regardless of the caller's working dir.
	binDir := config.GetBinFolderPath()
	base := "."
	if opts.ExePath != "" {
		base = filepath.Dir(opts.ExePath)
	}
	if !filepath.IsAbs(binDir) {
		binDir = filepath.Join(base, binDir)
	}
	removePath(r, binDir)

	// 10b. The other two directories that live beside the binary. `backups` holds
	//      copies of the DATABASE, i.e. every admin's bcrypt hash and every
	//      client's credentials, so leaving it on a decommissioned host is the
	//      worst of the leftovers even though it is the quietest. `cert` holds the
	//      panel's TLS key and any issued certificates.
	removePath(r, filepath.Join(base, "cert"))
	removePath(r, filepath.Join(base, "backups"))

	// 11. Kept — not removed (shared, or irreversible without a backup we never took).
	r.Kept = append(r.Kept,
		"distro packages (libreswan, nftables, iproute2/iproute, kernel-modules-extra) — remove with your package manager if unused elsewhere",
		"GRUB boot-default pin (GRUB_DEFAULT=saved in /etc/default/grub) — not reversible without your original",
		"/etc/modprobe.d un-blacklist edits — not reversible without your original",
	)

	// Defensive cleanup of legacy install locations the installer historically used.
	// New installs place the binary at /usr/local/bin/vpn-ui; remove the old path too.
	removePath(r, "/usr/local/bin/vpn-ui")
	removePath(r, "/usr/local/vpn-ui")

	logger.Info("uninstall: host teardown complete")
	return r
}

// stopVpnDaemons stops the supervised VPN daemons. procMgr.StopAll covers
// daemons this process started (a no-op for a fresh --uninstall invocation);
// pkill by resolved binary path then catches daemons a separately-running panel
// spawned, mirroring procmgr.go's orphan cleanup.
func stopVpnDaemons(r *UninstallReport, exePath string) {
	procMgr.StopAll()
	if !commandExists("pkill") {
		return
	}
	// accel-pppd and telemt were missing here even though the orphan reaper in
	// procmgr.go has known about them for as long as they have existed. Same
	// omission, same consequence: a daemon still holding :443 (or the MTProto
	// port) after the panel that supervised it is gone.
	for _, d := range []string{"openvpn", "xl2tpd", "pptpd", "accel-pppd", "telemt"} {
		bin := daemonBin(d)
		if bin == d {
			continue // unresolved bare name — avoid a too-broad match
		}
		_ = exec.Command("pkill", "-KILL", "-f", bin).Run()
	}
	// Both IPsec planes. libreswan's pluto is the legacy one; charon is the
	// SHARED plane that L2TP and IKEv2 both run on, so on any host that had
	// either of them a surviving charon holding UDP 500/4500 is the NORMAL
	// outcome, not an edge case.
	for _, p := range []string{
		backend.LibreswanBundleRoot + "/libexec/ipsec/pluto.bin",
		backend.StrongswanBundleRoot + "/libexec/ipsec/charon.bin",
	} {
		_ = exec.Command("pkill", "-KILL", "-f", p).Run()
	}
	// ocserv RETITLES its processes, so a -f match on the binary path misses
	// them; only an exact-name pass finds it. Same list procmgr.go reaps.
	for _, n := range []string{"ocserv-main", "ocserv-sm", "ocserv-worker", "ocserv"} {
		_ = exec.Command("pkill", "-KILL", "-x", n).Run()
	}
	// The Xray core is not a procMgr child, so nothing else stops it: the panel
	// is SIGKILLed below, which skips any shutdown hook, and it would be left
	// holding every inbound port plus the API port.
	if bin := xray.GetBinaryPath(); bin != "" {
		_ = exec.Command("pkill", "-KILL", "-f", bin).Run()
	}

	// Kill any OTHER panel process (e.g. the one the just-removed unit ran).
	// Exclude ourselves AND our ancestor chain: `pgrep -f <exePath>` also matches
	// the wrapper that launched us (under `incus exec`/ssh, `sh -c "<exePath>
	// --uninstall ..."` carries the exe path), and killing that parent severs the
	// caller's exec channel -> spurious 255 exit though teardown still completes.
	if exePath == "" {
		return
	}
	skip := map[string]bool{}
	for pid := os.Getpid(); pid > 1; {
		skip[strconv.Itoa(pid)] = true
		ppid := parentPID(pid)
		if ppid <= 1 || ppid == pid {
			break
		}
		pid = ppid
	}
	out, _ := exec.Command("pgrep", "-f", exePath).Output()
	for _, pid := range strings.Fields(string(out)) {
		if skip[pid] {
			continue
		}
		_ = exec.Command("kill", "-KILL", pid).Run()
	}
}

// parentPID returns the parent PID of pid by reading /proc/<pid>/stat, or 0 if it
// can't be determined. The comm field (2nd) may contain spaces and parentheses, so
// parse the fields AFTER the last ')': ppid is the second of those.
func parentPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+1 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}

// uninstallWarpSocks removes the official Cloudflare warp-cli (if present) via
// its bundled installer's --uninstall path, blocking until the background run
// finishes — a returning CLI would otherwise kill the goroutine mid-uninstall.
func uninstallWarpSocks(r *UninstallReport) {
	if !WarpSocksInstalled() {
		return
	}
	logger.Info("uninstall: removing cloudflare warp-cli")
	if !StartWarpSocks("uninstall", 0) {
		r.fail("warp uninstall", fmt.Errorf("another warp-cli run is already in progress"))
		return
	}
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		if st := WarpSocksState(); st.Done {
			if st.Success {
				r.Removed = append(r.Removed, "cloudflare-warp (warp-cli SOCKS)")
			} else {
				r.fail("warp uninstall", fmt.Errorf("uninstaller reported failure"))
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	r.fail("warp uninstall", fmt.Errorf("timed out after 3m"))
}

// removePath deletes a file or directory tree, recording the outcome. A path
// that's already absent is silently skipped (not an error).
func removePath(r *UninstallReport, path string) {
	if path == "" {
		return
	}
	if _, err := os.Lstat(path); err != nil {
		if !os.IsNotExist(err) {
			r.fail("stat "+path, err)
		}
		return
	}
	if err := os.RemoveAll(path); err != nil {
		r.fail("remove "+path, err)
		return
	}
	r.Removed = append(r.Removed, path)
}

// removeSymlinkIfTarget removes link only when it is a symlink pointing at
// wantTarget — so we never unlink a distro's own file that happens to share the
// path (e.g. a host-native /usr/sbin/pppd).
func removeSymlinkIfTarget(r *UninstallReport, link, wantTarget string) {
	dest, err := os.Readlink(link)
	if err != nil || dest != wantTarget {
		return
	}
	if err := os.Remove(link); err != nil {
		r.fail("remove symlink "+link, err)
		return
	}
	r.Removed = append(r.Removed, link+" -> "+wantTarget)
}
