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

	// KeepCores leaves every installed VPN core on the host: its daemon running,
	// its configs, its bundled tree, and the shared data plane it routes through.
	// Only the panel's own files go. Set by `--uninstall --cores keep`, for the
	// operator who is replacing or reinstalling the panel and does not want a
	// live VPN service torn down with it.
	KeepCores bool
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
//
// opts.KeepCores narrows the teardown to the panel itself: steps 3 and 5-10 are
// skipped whole, so every installed core keeps its daemon, its config and the
// data plane it needs. Each gate says why the step belongs to the cores, because
// several of them (the nftables table, the policy routing, the /etc/vpn-ui and
// sysctl drop-ins) are panel-NAMED but core-owned.
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
	//    KeepCores spares the CORE daemons only; the other-panel kill at the end
	//    of stopVpnDaemons always runs.
	stopVpnDaemons(r, opts.ExePath, opts.KeepCores)

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
	//
	//     Deliberately NOT gated by KeepCores, and do not "fix" that: these are the
	//     panel acting as a VPN CLIENT dialling out, not an installed core serving
	//     users here. Nothing keeps them alive once the panel is gone, so keeping
	//     them would only leave a dangling netdev routing into somebody else's VPN.
	var vpnOut VpnOutboundService
	if tunnels := vpnOut.List(); len(tunnels) > 0 {
		vpnOut.StopAll()
		for _, t := range tunnels {
			r.Removed = append(r.Removed, "vpn outbound tunnel "+t.Tag+" ("+t.Kind+")")
		}
	}

	// 3. Host ipsec.service (only present on the non-bundled libreswan path).
	//    Core-owned: it is the IPsec plane L2TP and IKEv2 ride on.
	if !opts.KeepCores && commandExists("systemctl") {
		_, _ = systemctl("disable", "--now", "ipsec")
	}

	// 4. Cloudflare warp-cli (SOCKS5), via its own bundled uninstaller. Ungated
	//    for the same reason as 2b: warp is an OUTBOUND this box dials out
	//    through, not one of the cores that serve users on it.
	uninstallWarpSocks(r)

	// Steps 5-9b are everything the installed CORES own: their units, the shared
	// data plane, their configs, their bundled trees. Then the restores that hand
	// the host back what provisioning took from it. KeepCores skips the lot.
	if !opts.KeepCores {
		// A whole-host uninstall releases every core's claim at once, so every
		// ownership question below is asked on behalf of all of them at once.
		allCores := installableCores()

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
		//
		//    Gated with the cores even though no coreSpec claims it: this table is
		//    the TPROXY hook that puts every core's traffic into Xray. Tear it down
		//    while "keeping" the cores and their daemons survive on disk, still
		//    listening, passing zero traffic. That is the worst possible outcome,
		//    because it looks like it worked.
		if commandExists("nft") {
			_ = exec.Command("nft", "delete", "table", "ip", "vpn").Run()
		}
		(&NftService{}).CleanupLegacyIptables()
		if firewalldRunning() {
			_ = exec.Command("firewall-cmd", "--zone=trusted", "--remove-source="+vpnAddrSpace).Run()
			_ = exec.Command("firewall-cmd", "--permanent", "--zone=trusted", "--remove-source="+vpnAddrSpace).Run()
		}

		// 7. Policy routing (fwmark 1 → table 100). Not reversed anywhere else, and
		//    the other half of step 6's data plane, so it is gated with it.
		//
		//    The rule is deleted unconditionally, on purpose, even though a host
		//    that already had its own `fwmark 1 lookup 100` never got a second one
		//    added and loses its only copy here. It is not in the ownership manifest
		//    because six separate SetupRouting copies add it, each skipping when the
		//    rule is already present: whichever protocol ran second would record
		//    "the operator had this" for a rule WE added. Half-recorded is worse
		//    than unrecorded, and a stray fwmark rule pointing at a flushed table
		//    100 blackholes traffic on a decommissioned host. Revisit only once one
		//    shared ensureVpnPolicyRoute() helper owns the add (see ownIpRule).
		//
		//    Removal now goes through that shared helper. The old loop here shelled
		//    out to `ip rule del fwmark 1 lookup 100` at most ten times, which was
		//    wrong twice over: it left every rule past the tenth behind on a host
		//    that had accumulated hundreds, and an `ip rule del` template treats the
		//    selectors it does not mention as wildcards, so it could take an
		//    operator's `from <addr> fwmark 1 lookup 100` with it.
		collapseVpnPolicyRules(true)
		if commandExists("ip") {
			_ = exec.Command("ip", "route", "flush", "table", "100").Run()
		}
		// rp_filter IS recorded, so it can be handed back. ensureVpnHostNetworking
		// relaxes it to 2 on every provisioning run and every SetupRouting, on a
		// host that may have chosen strict deliberately.
		if restored := restoreHostSysctls(); len(restored) > 0 {
			r.Removed = append(r.Removed, "restored host sysctls: "+strings.Join(restored, ", "))
		}

		// 8. /etc configs, runtime dirs, seq files, logs.
		//
		//    The panel-NAMED entries are gated with the rest, not split out: they
		//    are named after the panel but owned by the cores. modules-load.d/vpn-ui.conf
		//    is what loads ppp/l2tp/gre at boot, sysctl.d/99-vpn-ui.conf turns on
		//    forwarding, and the log folder is where a surviving Xray keeps writing
		//    its access and IP-limit logs. A kept core needs every one of them.
		//
		//    /etc/vpn-ui is NOT in either list here. It holds ownership.json and
		//    backups/, which every restore below reads from, so it goes last inside
		//    this gate. See the end of the block.
		//
		//    Panel-private by name: nothing else on this host is called these, so
		//    they can go straight out.
		for _, p := range []string{
			"/etc/ppp/radius", // panel-owned subdir of the host /etc/ppp
			"/etc/swanctl/conf.d/l2tp.conf",
			"/etc/modules-load.d/vpn-ui.conf",
		} {
			removePath(r, p)
		}
		// Shared with a distro package: the manifest decides, not this list. A file
		// we created is removed; one we OVERWROTE is restored from the copy taken
		// before the first overwrite; one nobody recorded is reported and left
		// alone. This is what stops a whole-host uninstall destroying a host
		// libreswan's PSKs, or a distro xl2tpd's and pptpd's configs.
		//
		// The last three are new here. /etc/strongswan.conf also reaches release via
		// removeFeature(featStrongswan) in step 9b and is idempotent either way;
		// swanctl.conf and /etc/default/grub were never touched at all before, and
		// adding them is what gives the operator back their swanctl connections and
		// their GRUB default.
		for _, p := range []string{
			"/etc/xl2tpd/xl2tpd.conf",
			"/etc/ppp/options.xl2tpd",
			"/etc/ipsec.conf",
			"/etc/ipsec.secrets",
			"/etc/pptpd.conf",
			"/etc/ppp/pptpd-options",
			"/etc/sysctl.d/99-vpn-ui.conf",
			"/etc/strongswan.conf",
			"/etc/swanctl/swanctl.conf",
			"/etc/default/grub",
		} {
			releaseOwned(r, p, allCores)
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
		//
		//     The catalog still names the paths but no longer decides their fate:
		//     openconnect's spec.paths is /etc/ocserv, which on a host with a distro
		//     ocserv holds THEIR ocserv.conf, certificates and ocpasswd, and
		//     openvpn's globs include /etc/openvpn/server, the distro's own config
		//     dir that the panel only ever MkdirAlls. Globs run BEFORE paths so a
		//     shared root is already empty by the time the root itself is judged.
		for _, spec := range coreCatalog {
			if spec.builtin {
				continue
			}
			for _, g := range spec.globs {
				matches, err := filepath.Glob(g)
				if err != nil {
					continue
				}
				for _, m := range matches {
					releaseOwned(r, m, allCores)
				}
			}
			for _, p := range spec.paths {
				releaseOwned(r, p, allCores)
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

		// 9c. Host state provisioning CHANGED rather than created, handed back now
		//     that no core is left to need it. migrateFromSystemd disabled the
		//     host's own openvpn-server@/xl2tpd/pptpd/ipsec units so the panel could
		//     run those daemons itself, and GRE's FOU mode turned GRO off on the WAN
		//     NIC; neither was ever replayed, so an uninstalled host kept its
		//     services stopped and its NIC changed forever. Both are no-ops when
		//     nothing was recorded, so they are safe on a host upgraded from a build
		//     that predates the manifest.
		emit := func(st ProvisionStep) { r.Removed = append(r.Removed, st.Name+": "+st.Msg) }
		if line := restoreDisabledUnits(allCores, emit); line != "" {
			r.Kept = append(r.Kept, line)
		}
		restoreEthtoolState(allCores, emit)

		// 9d. The /etc/modprobe.d blacklists provisioning rewrote in place. Driven
		//     off the manifest rather than a literal list because the filenames vary
		//     per distro. Gated with the cores for the same reason modules-load.d is:
		//     putting a blacklist back while the cores stay would break them at the
		//     next boot, which is the opposite of what --cores keep asked for.
		for _, p := range ownIDsOfKind(ownFile) {
			if !strings.HasPrefix(p, "/etc/modprobe.d/") {
				continue
			}
			releaseOwned(r, p, allCores)
		}

		// LAST inside this gate, and it must stay last: /etc/vpn-ui holds
		// ownership.json and backups/, which every restore above reads from. Removed
		// any earlier and those restores silently find their backup gone (they fail
		// safe and report "kept: its backup is missing", so the operator simply
		// never gets their config back). It is also why nothing below may call into
		// the manifest again: ownSaveLocked MkdirAlls this directory, so a later
		// write would resurrect it on a fully uninstalled host.
		removePath(r, "/etc/vpn-ui") // nft config dir (vpn.nft) + ownership manifest
	}

	// The install dir and the bin/ dir under it, resolved once: a relative bin/
	// path resolves against the EXE's dir, not the caller's working dir. Both are
	// computed outside the KeepCores gate because 10b needs base either way and
	// step 11 names binDir when it was spared.
	base := "."
	if opts.ExePath != "" {
		base = filepath.Dir(opts.ExePath)
	}
	binDir := config.GetBinFolderPath()
	if !filepath.IsAbs(binDir) {
		binDir = filepath.Join(base, binDir)
	}

	// 10. The bin/ dir next to the binary (xray core, geo files, config.json, and
	//     the flat VPN daemons — all extract here now). Core-owned in full: a kept
	//     core runs its daemon straight out of here, and the ones that route
	//     through Xray need the core and the geo files too.
	if !opts.KeepCores {
		removePath(r, binDir)
	}

	// 10b. The other two directories that live beside the binary. `backups` holds
	//      copies of the DATABASE, i.e. every admin's bcrypt hash and every
	//      client's credentials, so leaving it on a decommissioned host is the
	//      worst of the leftovers even though it is the quietest. `cert` holds the
	//      panel's TLS key and any issued certificates.
	removePath(r, filepath.Join(base, "cert"))
	removePath(r, filepath.Join(base, "backups"))

	// 11. Kept — not removed (shared with the rest of the host).
	//
	//     The GRUB pin and the /etc/modprobe.d edits used to be listed here as "not
	//     reversible without your original". They are reversible now: bootloader.go
	//     and pkgmgr.go each back the file up before their first edit, and step 8
	//     and 9d hand them back. Do not put those lines back without checking that
	//     the backups stopped being taken.
	r.Kept = append(r.Kept,
		"distro packages (libreswan, nftables, iproute2/iproute, kernel-modules-extra) — remove with your package manager if unused elsewhere",
	)
	// What the manifest recorded as NOT ours, so the operator can see the things
	// this uninstall deliberately walked past. Surfacing this is the operator-facing
	// point of the whole manifest. Read-only, and the manifest is cached in memory
	// after its first read, so this still works once /etc/vpn-ui is gone.
	for _, a := range OwnershipReport() {
		if a.PreExisting != "no" {
			r.Kept = append(r.Kept, a.Kind+" "+a.ID+" ("+a.Note+")")
		}
	}
	// What KeepCores spared, spelled out: the operator asked for it, but the last
	// line is the part nobody expects, so it is stated rather than implied.
	if opts.KeepCores {
		r.Kept = append(r.Kept,
			"the installed VPN cores (--cores keep): daemons left running, plus their /etc configs, bundled trees and "+binDir,
			"the data plane they need: nftables 'ip vpn' table, firewalld trust, fwmark-1/table-100 routing, /etc/vpn-ui, the modules-load.d and sysctl.d drop-ins, "+config.GetLogFolder(),
			"the host state provisioning changed for them: the GRUB boot-default pin, the /etc/modprobe.d un-blacklists, the relaxed rp_filter, any host units it disabled and any NIC offload it turned off. The originals are in /etc/vpn-ui/backups/ with /etc/vpn-ui/ownership.json listing them, so this is reversible by hand once the cores are gone too",
			"NOTE: RADIUS ran INSIDE this binary, so kept L2TP, PPTP, OpenVPN, OpenConnect, SSTP and IKEv2 cores can no longer authenticate new logins. WireGuard, AmneziaWG, GRE and MTProto are unaffected",
		)
	}

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
//
// keepCores skips the core daemons and nothing else. The other-panel kill at the
// end still runs: that is the panel, which is being removed either way.
func stopVpnDaemons(r *UninstallReport, exePath string, keepCores bool) {
	procMgr.StopAll()
	// The core daemons die only when the cores are being removed. Under
	// --cores keep the operator asked for a working VPN to survive the panel, and
	// a daemon still serving its port is the most working state available: it has
	// its config, it has its sockets, and there is nothing left to restart it if
	// we kill it here. procMgr.StopAll above is exempt because it only reaches
	// children of THIS process, which on a fresh --uninstall run is nothing.
	if !keepCores && commandExists("pkill") {
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

// releaseOwned is removePath's manifest-aware counterpart, for a path that may be
// shared with a distro package. removePath answers one question, "delete it";
// this answers three, "delete it", "put the operator's original back", or "leave
// it alone and say why", and records whichever happened. Every caller pairs it
// with the full core list, because a whole-host uninstall releases every claim.
func releaseOwned(r *UninstallReport, path string, cores []string) {
	if removed, kept := ownReleasePath(path, cores); removed != "" {
		r.Removed = append(r.Removed, removed)
	} else if kept != "" {
		r.Kept = append(r.Kept, kept)
	}
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
