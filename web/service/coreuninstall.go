package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/logger"
)

// Per-core uninstall.
//
// The rule that makes this safe is reference counting against what REMAINS
// installed, never against what is being removed. IPsec is the case that forces
// it: L2TP and IKEv2 both stand on the one bundled strongSwan/charon, so
// removing IKEv2 while L2TP is still installed must take IKEv2's own swanctl
// connections and config root and leave the charon bundle, the /usr/lib/ipsec
// link and the daemon itself completely alone. The same arithmetic covers pppd
// (L2TP + PPTP), the PPP kernel-modules package (L2TP + PPTP), and every module
// two cores happen to share.
//
// Distro packages are never removed, matching the whole-host Uninstall policy:
// the panel cannot know whether something else on the machine depends on
// libreswan or a kernel package it installed, so it reports them as kept.

// CoreUninstallReport records what removing one or more cores actually did.
type CoreUninstallReport struct {
	// Cores is the cores that were removed.
	Cores []string `json:"cores"`
	// Steps mirrors provisioning's step stream so the same live console can
	// render an uninstall.
	Steps []ProvisionStep `json:"steps"`
	// Kept is the shared requirements deliberately left in place, each with the
	// still-installed core that needs it. This is the operator-facing proof that
	// removing IKEv2 did not break L2TP.
	Kept []string `json:"kept"`
}

// coreUninstallRun holds the single in-flight or most recent uninstall, polled
// by the Core Settings page exactly like a provisioning run.
var coreUninstallRun struct {
	mu      sync.Mutex
	running bool
	done    bool
	steps   []ProvisionStep
	kept    []string
	cores   []string
}

// CoreUninstallState is a snapshot of the background uninstall run.
type CoreUninstallState struct {
	Running bool            `json:"running"`
	Done    bool            `json:"done"`
	Steps   []ProvisionStep `json:"steps"`
	Kept    []string        `json:"kept"`
	Cores   []string        `json:"cores"`
}

// CoreUninstallStatus returns the current/most-recent uninstall run's progress.
func (s *CoreService) CoreUninstallStatus() CoreUninstallState {
	coreUninstallRun.mu.Lock()
	defer coreUninstallRun.mu.Unlock()
	steps := make([]ProvisionStep, len(coreUninstallRun.steps))
	copy(steps, coreUninstallRun.steps)
	kept := make([]string, len(coreUninstallRun.kept))
	copy(kept, coreUninstallRun.kept)
	cores := make([]string, len(coreUninstallRun.cores))
	copy(cores, coreUninstallRun.cores)
	return CoreUninstallState{
		Running: coreUninstallRun.running,
		Done:    coreUninstallRun.done,
		Steps:   steps,
		Kept:    kept,
		Cores:   cores,
	}
}

// Inbound dispositions for a core uninstall. A core's inbounds cannot simply be
// ignored: the daemon serving them is about to be removed.
const (
	// InboundsBlock is the default and the only one that refuses. It exists so a
	// caller that never asked the question (the CLI, an old client) still cannot
	// silently strand inbounds.
	InboundsBlock = ""
	// InboundsDelete removes the core's inbounds along with it.
	InboundsDelete = "delete"
	// InboundsKeep leaves them in the database, deliberately non-functional, so
	// the operator can reinstall the core later and have them work again.
	InboundsKeep = "keep"
)

// CanUninstallCores reports whether the selection can be removed, given what the
// caller decided to do with any inbounds those cores still serve.
func (s *CoreService) CanUninstallCores(names []string, inbounds string) error {
	selected := validCoreNames(names)
	if len(selected) == 0 {
		return fmt.Errorf("no installable core selected")
	}
	installed := s.provisionedProtocolSet()
	counts := s.inboundCountsByCore()
	for _, n := range selected {
		if !installed[n] {
			return fmt.Errorf("%s is not installed", coreDisplayName(n))
		}
		// Only an undecided caller is refused. Once the operator has been shown
		// the choice and made it, both answers are legitimate: delete the
		// inbounds, or keep them and accept that they stop working until the
		// core is reinstalled.
		if counts[n] > 0 && inbounds != InboundsDelete && inbounds != InboundsKeep {
			return fmt.Errorf("%s still has %d inbound(s); choose whether to delete them or keep them",
				coreDisplayName(n), counts[n])
		}
	}
	return nil
}

// deleteCoreInbounds removes every inbound served by the given cores. Used for
// the InboundsDelete disposition, before the daemons go away.
func (s *CoreService) deleteCoreInbounds(names []string) (int, error) {
	wanted := map[string]bool{}
	for _, n := range validCoreNames(names) {
		wanted[n] = true
	}
	var inboundService InboundService
	all, err := inboundService.GetAllInbounds()
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, in := range all {
		if !wanted[protocolCoreName(string(in.Protocol))] {
			continue
		}
		if _, err := inboundService.DelInbound(in.Id); err != nil {
			return removed, fmt.Errorf("deleting inbound %q: %w", in.Remark, err)
		}
		removed++
	}
	return removed, nil
}

// StartCoreUninstall removes the given cores in the background, returning false
// if a provisioning or uninstall run is already in flight (they touch the same
// files, so they must not overlap).
func (s *CoreService) StartCoreUninstall(names []string, inbounds string) (bool, error) {
	if err := s.CanUninstallCores(names, inbounds); err != nil {
		return false, err
	}
	// Delete BEFORE the daemons go, so the normal delete path still has a live
	// backend to tear each inbound's own state down with.
	if inbounds == InboundsDelete {
		if n, err := s.deleteCoreInbounds(names); err != nil {
			return false, err
		} else if n > 0 {
			logger.Info("core uninstall: deleted", n, "inbound(s) belonging to", names)
		}
	}
	provisionRun.mu.Lock()
	provisioning := provisionRun.running
	provisionRun.mu.Unlock()
	if provisioning {
		return false, fmt.Errorf("setup is running; wait for it to finish")
	}

	coreUninstallRun.mu.Lock()
	if coreUninstallRun.running {
		coreUninstallRun.mu.Unlock()
		return false, fmt.Errorf("an uninstall is already running")
	}
	selected := validCoreNames(names)
	coreUninstallRun.running = true
	coreUninstallRun.done = false
	coreUninstallRun.steps = nil
	coreUninstallRun.kept = nil
	coreUninstallRun.cores = selected
	coreUninstallRun.mu.Unlock()

	go func() {
		var cs CoreService
		kept := cs.runCoreUninstall(selected, func(st ProvisionStep) {
			coreUninstallRun.mu.Lock()
			coreUninstallRun.steps = append(coreUninstallRun.steps, st)
			coreUninstallRun.mu.Unlock()
		})
		coreUninstallRun.mu.Lock()
		coreUninstallRun.running = false
		coreUninstallRun.done = true
		coreUninstallRun.kept = kept
		coreUninstallRun.mu.Unlock()
	}()
	return true, nil
}

// UninstallCores removes cores synchronously and returns the full report. This
// is the collected form of StartCoreUninstall, for the CLI and for tests.
func (s *CoreService) UninstallCores(names []string, inbounds string) (*CoreUninstallReport, error) {
	if err := s.CanUninstallCores(names, inbounds); err != nil {
		return nil, err
	}
	selected := validCoreNames(names)
	rep := &CoreUninstallReport{Cores: selected}
	rep.Kept = s.runCoreUninstall(selected, func(st ProvisionStep) {
		rep.Steps = append(rep.Steps, st)
	})
	return rep, nil
}

// runCoreUninstall does the work and streams a step per action. It returns the
// shared requirements that were kept, each annotated with who still needs them.
//
// Order matters: stop the daemons before deleting the binaries and configs they
// are running from, and only then rewrite the host-level state (module persist,
// provisioned list) that describes what is left.
func (s *CoreService) runCoreUninstall(selected []string, emit func(ProvisionStep)) []string {
	removing := map[string]bool{}
	for _, n := range selected {
		removing[n] = true
	}
	// What survives. Every "may I remove this shared thing?" question is asked
	// of THIS set, which is the whole safety property.
	var remaining []string
	for _, n := range s.installedCoreNames() {
		if !removing[n] {
			remaining = append(remaining, n)
		}
	}

	// 1. Stop the daemons first, so nothing is executing from a path about to be
	//    unlinked and no supervisor restarts it mid-teardown.
	//
	//    Except where the daemon is SHARED and a surviving core still needs it.
	//    IKEv2 and L2TP/IPsec are one charon process, so StopCore("ikev2") would
	//    drop live L2TP tunnels as a side effect of removing IKEv2. In that case
	//    the daemon is left running and step 7 reloads it without the removed
	//    core's connections instead.
	for _, n := range selected {
		if keeper := sharedDaemonKeeper(n, remaining); keeper != "" {
			emit(ProvisionStep{Name: "stop " + coreDisplayName(n), OK: true,
				Msg: "left running: the same daemon still serves " + coreDisplayName(keeper)})
			continue
		}
		if err := s.StopCore(n); err != nil {
			// A core with nothing running reports an error here, which is the
			// normal case for an idle core: note it and carry on.
			emit(ProvisionStep{Name: "stop " + coreDisplayName(n), OK: true, Warn: true, Msg: err.Error()})
			continue
		}
		emit(ProvisionStep{Name: "stop " + coreDisplayName(n), OK: true, Msg: "stopped"})
	}

	// 2. The cores' own config files and per-inbound directories.
	for _, n := range selected {
		spec := coreSpecFor(n)
		if spec == nil {
			continue
		}
		var removed []string
		for _, p := range spec.paths {
			if removeIfPresent(p) {
				removed = append(removed, p)
			}
		}
		for _, g := range spec.globs {
			matches, _ := filepath.Glob(g)
			for _, m := range matches {
				if removeIfPresent(m) {
					removed = append(removed, m)
				}
			}
		}
		emit(ProvisionStep{Name: "remove " + coreDisplayName(n) + " config", OK: true,
			Msg: pathsMsg(removed)})
	}

	// 3. Bundled daemon binaries, minus anything a surviving core still runs
	//    (pptpctrl belongs to PPTP alone, but the principle is the same).
	keepBins := map[string]bool{}
	for _, d := range daemonsFor(remaining) {
		keepBins[d] = true
	}
	var dropBins []string
	for _, d := range daemonsFor(selected) {
		if !keepBins[d] {
			dropBins = append(dropBins, d)
		}
	}
	if len(dropBins) > 0 {
		removed, err := backend.RemoveDaemons(dropBins)
		emit(ProvisionStep{Name: "remove bundled binaries", OK: err == nil,
			Msg: pathsMsg(removed), Log: errText(err)})
	}

	// 4. Shared features. Each is undone only when NO surviving core claims it.
	//    This is the ipsec case the whole design exists for.
	var kept []string
	for _, feat := range []string{featPppd, featPptpCtrl, featAccel, featStrongswan, featKernelMods, featAmneziawg} {
		if !needsFeature(selected, feat) {
			continue
		}
		if needsFeature(remaining, feat) {
			kept = append(kept, fmt.Sprintf("%s (still needed by %s)",
				featureLabel(feat), strings.Join(coreDisplayNames(coresNeeding(remaining, feat)), ", ")))
			emit(ProvisionStep{Name: "keep " + featureLabel(feat), OK: true,
				Msg: "still required by " + strings.Join(coreDisplayNames(coresNeeding(remaining, feat)), ", ")})
			continue
		}
		emit(removeFeature(feat))
	}

	// 5. Rewrite the module-persist file for what is left, so the removed cores'
	//    modules stop being auto-loaded on boot. Loaded modules are deliberately
	//    NOT rmmod'd: unloading a live module can drop unrelated traffic, and it
	//    buys nothing that the next boot does not.
	if len(remaining) == 0 {
		emit(ProvisionStep{Name: "persist /etc/modules-load.d/vpn-ui.conf", OK: true,
			Msg: removedMsg(removeIfPresent("/etc/modules-load.d/vpn-ui.conf"))})
	} else {
		mods := requiredModulesFor(remaining)
		for _, m := range optionalModulesFor(remaining) {
			if moduleAvailable(m) {
				mods = append(mods, m)
			}
		}
		err := os.WriteFile("/etc/modules-load.d/vpn-ui.conf", []byte(strings.Join(dedupe(mods), "\n")+"\n"), 0644)
		emit(ProvisionStep{Name: "persist /etc/modules-load.d/vpn-ui.conf", OK: err == nil,
			Msg: msgOrOK(err)})
	}

	// 6. Record what the host is now installed for. Done last: everything above
	//    reads the old set, and a crash part-way leaves the core still listed as
	//    installed, which is the safe direction to fail in (re-running the
	//    uninstall finishes the job; the alternative silently strands files).
	var ss SettingService
	if err := ss.SetProvisionedProtocols(orderedCoreNames(remaining)); err != nil {
		logger.Warning("core uninstall: failed to persist provisionedProtocols:", err)
		emit(ProvisionStep{Name: "record installed cores", OK: false, Msg: err.Error()})
	} else {
		emit(ProvisionStep{Name: "record installed cores", OK: true, Msg: installedMsg(remaining)})
	}

	// 7. Reconcile the survivors that shared something with what was removed:
	//    regenerate their configs and bring their daemon back to the right state.
	//    This is what makes the charon case correct end to end. The removed
	//    core's swanctl connection files are gone by now, so re-initialising L2TP
	//    reloads charon with only L2TP's own configuration.
	//
	//    Scoped to the affected cores on purpose: restarting every daemon on the
	//    host to remove one unrelated core would be an outage nobody asked for.
	if affected := coresSharingWith(selected, remaining); len(affected) > 0 {
		s.reinitCores(affected)
		emit(ProvisionStep{Name: "reconcile shared cores", OK: true,
			Msg: strings.Join(coreDisplayNames(affected), ", ")})
	}

	// Nftables/routing are shared by the whole data plane and stay put; the
	// removed cores simply stop having inbounds in them.
	return kept
}

// sharedDaemonKeeper returns the first remaining core that runs the SAME daemon
// process as `name`, or "" when stopping `name` affects nothing else.
//
// Today strongSwan/charon is the only shared daemon: one process serves both
// IKEv2 and L2TP/IPsec. pppd and accel-ppp are per-core processes, so removing
// one of those cores stops only its own.
func sharedDaemonKeeper(name string, remaining []string) string {
	if !coreHasFeature(name, featStrongswan) {
		return ""
	}
	for _, r := range coresNeeding(remaining, featStrongswan) {
		return r
	}
	return ""
}

// coreHasFeature reports whether one core claims a feature.
func coreHasFeature(name, feat string) bool {
	return needsFeature([]string{name}, feat)
}

// coresSharingWith returns the cores in `remaining` that claim at least one
// feature with any of the `removed` cores, i.e. exactly those whose host state
// the removal could have disturbed.
func coresSharingWith(removed, remaining []string) []string {
	var out []string
	for _, r := range specsFor(remaining) {
		for _, d := range specsFor(removed) {
			if sharesAnyFeature(r, d) {
				out = append(out, r.name)
				break
			}
		}
	}
	return out
}

// reinitCores regenerates configuration and restarts the daemons for the given
// cores, using the very same Init* entry points a completed setup run calls.
func (s *CoreService) reinitCores(names []string) {
	for _, n := range names {
		switch n {
		case "l2tp":
			s.l2tpService.InitL2tp()
		case "pptp":
			s.pptpService.InitPptp()
		case "openvpn":
			s.openvpnService.InitOpenVpn()
		case "openconnect":
			s.ocservService.InitOcserv()
		case "sstp":
			s.sstpService.InitSstp()
		case "ikev2":
			s.ikev2Service.InitIkev2()
		}
	}
}

// coresNeeding lists which of the given cores claim a feature.
func coresNeeding(names []string, feat string) []string {
	var out []string
	for _, c := range specsFor(names) {
		for _, f := range c.feats {
			if f == feat {
				out = append(out, c.name)
				break
			}
		}
	}
	return out
}

// removeFeature undoes one provisioning feature. Only reached when no installed
// core still needs it.
func removeFeature(feat string) ProvisionStep {
	switch feat {
	case featPppd:
		// The bundle owns sbin/ and lib/ under the root; the root ITSELF is
		// shared (LinkPptpCtrl drops pptpctrl straight into it), so the two
		// subtrees go and the root is only pruned once it is empty.
		var removed []string
		if unlinkIfPointsAt(backend.PppdSystem, backend.PppdBundled) {
			removed = append(removed, backend.PppdSystem)
		}
		if unlinkIfPointsAt(backend.PppdPluginDir, backend.PppdBundleRoot+"/lib/pppd") {
			removed = append(removed, backend.PppdPluginDir)
		}
		for _, sub := range []string{"/sbin", "/lib"} {
			if removeIfPresent(backend.PppdBundleRoot + sub) {
				removed = append(removed, backend.PppdBundleRoot+sub)
			}
		}
		if removeDirIfEmpty(backend.PppdBundleRoot) {
			removed = append(removed, backend.PppdBundleRoot)
		}
		return ProvisionStep{Name: "remove pppd bundle", OK: true, Msg: pathsMsg(removed)}

	case featPptpCtrl:
		var removed []string
		if unlinkAny(backend.PptpCtrlLink) {
			removed = append(removed, backend.PptpCtrlLink)
		}
		// Same shared root as pppd: whichever of the two is removed last is the
		// one that gets to take the directory with it.
		if removeDirIfEmpty(backend.PppdBundleRoot) {
			removed = append(removed, backend.PppdBundleRoot)
		}
		return ProvisionStep{Name: "remove pptpctrl link", OK: true, Msg: pathsMsg(removed)}

	case featAccel:
		var removed []string
		if unlinkAny(backend.AccelModuleDir) {
			removed = append(removed, backend.AccelModuleDir)
		}
		if removeIfPresent(backend.AccelBundleRoot) {
			removed = append(removed, backend.AccelBundleRoot)
		}
		return ProvisionStep{Name: "remove accel-ppp (SSTP) bundle", OK: true, Msg: pathsMsg(removed)}

	case featStrongswan:
		// Reached only when neither L2TP nor IKEv2 is installed any more, so the
		// shared charon has no user left.
		var removed []string
		if unlinkAny(backend.StrongswanIpsecDir) {
			removed = append(removed, backend.StrongswanIpsecDir)
		}
		if removeIfPresent(backend.StrongswanBundleRoot) {
			removed = append(removed, backend.StrongswanBundleRoot)
		}
		if removeIfPresent("/etc/strongswan.conf") {
			removed = append(removed, "/etc/strongswan.conf")
		}
		// charon's control socket. Removed HERE rather than from the ikev2 catalog
		// entry precisely because charon is shared: this branch only runs once
		// neither L2TP nor IKEv2 is left, so deleting the socket cannot pull it out
		// from under a still-running charon that L2TP is using.
		if removeIfPresent("/var/run/charon.vici") {
			removed = append(removed, "/var/run/charon.vici")
		}
		// The shared charon config root. Named after IKEv2 for historical reasons
		// but written for L2TP too, so it can only go once neither remains.
		if removeIfPresent(ikev2ConfigRoot) {
			removed = append(removed, ikev2ConfigRoot)
		}
		return ProvisionStep{Name: "remove strongSwan (IPsec) bundle", OK: true, Msg: pathsMsg(removed)}

	case featKernelMods:
		// The distro kernel package is never removed: it is the host's kernel,
		// and something else may well depend on it now.
		return ProvisionStep{Name: "kernel-modules package", OK: true,
			Msg: "kept (a distro package; remove it yourself if nothing else needs it)"}

	case featAmneziawg:
		return removeAmneziawgModule()
	}
	return ProvisionStep{Name: "remove " + feat, OK: true, Msg: "nothing to do"}
}

// featureLabel names a feature for the operator.
func featureLabel(feat string) string {
	switch feat {
	case featPppd:
		return "pppd bundle"
	case featPptpCtrl:
		return "pptpctrl link"
	case featAccel:
		return "accel-ppp bundle"
	case featStrongswan:
		return "strongSwan/IPsec (charon)"
	case featKernelMods:
		return "PPP kernel-modules package"
	case featAmneziawg:
		return "AmneziaWG kernel module"
	}
	return feat
}

// coreDisplayName is the catalog title, falling back to the raw name.
func coreDisplayName(name string) string {
	if c := coreSpecFor(name); c != nil {
		return c.title
	}
	return name
}

func coreDisplayNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, coreDisplayName(n))
	}
	return out
}

// removeIfPresent deletes a path and reports whether anything was there.
func removeIfPresent(path string) bool {
	if path == "" {
		return false
	}
	if _, err := os.Lstat(path); err != nil {
		return false
	}
	if err := os.RemoveAll(path); err != nil {
		logger.Warning("core uninstall: remove", path, err)
		return false
	}
	return true
}

// removeDirIfEmpty deletes a directory only when nothing is left in it. Used for
// the roots two features share (/usr/libexec/vpn-ui holds both the pppd bundle
// and the pptpctrl link), so whichever feature is removed last takes the
// directory and neither takes it early.
func removeDirIfEmpty(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) > 0 {
		return false
	}
	return os.Remove(path) == nil
}

// unlinkIfPointsAt removes link only when it is a symlink to wantTarget, so a
// distro's own file at the same path is never touched.
func unlinkIfPointsAt(link, wantTarget string) bool {
	dest, err := os.Readlink(link)
	if err != nil || dest != wantTarget {
		return false
	}
	return os.Remove(link) == nil
}

// unlinkAny removes a path only when it is a symlink. The linked-in directories
// (/usr/lib/ipsec, /usr/lib/accel-ppp) may exist as a real distro directory on a
// host that also has its own strongSwan or accel-ppp, and that is not ours.
func unlinkAny(link string) bool {
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		return false
	}
	return os.Remove(link) == nil
}

func pathsMsg(paths []string) string {
	if len(paths) == 0 {
		return "nothing to do"
	}
	if len(paths) <= 3 {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%d path(s): %s, ...", len(paths), strings.Join(paths[:3], ", "))
}

func removedMsg(removed bool) string {
	if removed {
		return "removed"
	}
	return "nothing to do"
}

func installedMsg(remaining []string) string {
	if len(remaining) == 0 {
		return "no cores installed"
	}
	return strings.Join(coreDisplayNames(remaining), ", ")
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
