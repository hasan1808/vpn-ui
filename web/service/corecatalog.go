package service

import (
	"sort"

	"github.com/hasan1808/pro-ui/backend"
)

// The core catalog: what each installable VPN core actually needs from the host.
//
// Setup used to be all-or-nothing. It ran every step for every protocol, so a
// host that only ever wanted WireGuard still got pppd, accel-ppp, strongSwan and
// a kernel-modules package it had no use for. The catalog below replaces that
// with one declarative row per core, which three things then read:
//
//   - provisioning, to run only the steps the selected cores need;
//   - the system status card, so a module belonging to a core nobody installed
//     is not reported missing;
//   - uninstall, which removes a core's own artifacts and keeps every shared one
//     that a still-installed core continues to need.
//
// That last point is the reason requirements are named rather than inlined: with
// ipsec listed by BOTH l2tp and ikev2, "remove ikev2" can see that l2tp still
// claims strongSwan and leave the bundle alone.

// Provisioning features: host work that is not a kernel module or a bundled
// daemon binary. A core lists the ones it needs and the provisioner runs each
// exactly once for the whole selection, however many cores asked for it.
const (
	// featPppd extracts the relocatable pppd tree and points the system pppd +
	// plugin dir at it. Needed by the daemons that drive kernel PPP through
	// pppd itself (xl2tpd, pptpd). accel-ppp does NOT need it: it implements
	// PPP in-process and only wants the ppp_generic kernel module.
	featPppd = "pppd"
	// featPptpCtrl symlinks pptpd's compiled-in pptpctrl path at the bundle.
	featPptpCtrl = "pptpctrl"
	// featAccel extracts the accel-ppp tree and links its module dir, so the
	// bare module names in the generated accel-ppp.conf resolve.
	featAccel = "accel"
	// featStrongswan extracts strongSwan and links /usr/lib/ipsec. This is the
	// shared IPsec data plane: ONE charon serves IKEv2 and L2TP/IPsec both, so
	// two cores claim it and it survives either one being removed alone. On an
	// architecture with no strongSwan bundle it falls back to host libreswan.
	featStrongswan = "strongswan"
	// featKernelMods installs the distro's fuller kernel-modules package when
	// the running kernel lacks the PPP/L2TP modules, pinning the bootloader and
	// asking for a reboot when they only ship in a kernel that is not booted.
	featKernelMods = "kernelmods"
	// featAmneziawg DKMS-builds the out-of-tree amneziawg module. The project's
	// only on-host compile, so it is scoped tightly to the one core that needs it.
	featAmneziawg = "amneziawg"
)

// coreSpec is one row of the catalog.
type coreSpec struct {
	name    string
	title   string // display name, matches core.html's coreTitle map
	backend string // the software that powers it
	// desc is a one-line "what you get", shown beside the checkbox so an
	// operator picking cores does not have to already know the protocol list.
	desc string

	// modules are kernel modules this core cannot work without. optModules are
	// loaded when the kernel ships them but never block setup or drive a
	// kernel-package install (see vpnOptionalKernelModules for why).
	modules    []string
	optModules []string
	// daemons are bundled binaries extracted flat into BinDir.
	daemons []string
	// feats are the provisioning features above.
	feats []string

	// paths are the config files and runtime dirs this core owns outright, and
	// globs are the per-inbound ones. Both are removed when it is uninstalled;
	// nothing shared belongs here (shared state is reference-counted through
	// feats instead).
	paths []string
	globs []string

	// builtin marks a core with no host prerequisites at all: it runs inside
	// the panel process. Those are always available and never offered for
	// install or removal.
	builtin bool

	// usesRadius marks a core that authenticates against the in-binary RADIUS
	// server. RADIUS ships inside the panel and has no install step of its own,
	// so this is the only thing that decides whether it has anything on this
	// host to serve. Deliberately NOT a feats entry: feats also drive sharersOf
	// and the uninstall reconcile sweep, and RADIUS is never installed or
	// removed, so listing it there would make all six consumers claim to share
	// a requirement with each other.
	usesRadius bool
}

// coreCatalog is ordered the way the setup dialog lists the cores: the
// long-standing dial-in protocols first, then the modern tunnels, then the
// relays. Adding a core here is all that is needed for it to appear in setup,
// be counted by the shared-requirement logic, and be uninstallable.
var coreCatalog = []coreSpec{
	{
		name: "l2tp", title: "L2TP", backend: "xl2tpd",
		desc:       "L2TP/IPsec dial-in, native on Windows, macOS, iOS and Android",
		usesRadius: true,
		modules:    []string{"ppp_generic", "l2tp_ppp", "ppp_mppe"},
		optModules: []string{"af_key", "esp4", "xfrm_user"},
		daemons:    []string{"xl2tpd", "xl2tpd-control"},
		feats:      []string{featPppd, featStrongswan, featKernelMods},
		paths: []string{
			"/etc/xl2tpd/xl2tpd.conf",
			"/etc/ppp/options.xl2tpd",
			"/etc/swanctl/conf.d/l2tp.conf",
			"/var/run/xl2tpd",
		},
	},
	{
		name: "pptp", title: "PPTP", backend: "pptpd",
		desc:       "Legacy PPTP dial-in for old clients",
		usesRadius: true,
		modules:    []string{"ppp_generic", "nf_conntrack_pptp", "ip_gre", "ppp_mppe"},
		daemons:    []string{"pptpd", "pptpctrl"},
		feats:      []string{featPppd, featPptpCtrl, featKernelMods},
		paths: []string{
			"/etc/pptpd.conf",
			"/etc/ppp/pptpd-options",
		},
	},
	{
		name: "openvpn", title: "OpenVPN", backend: "OpenVPN",
		desc:       "OpenVPN over TCP and UDP with downloadable .ovpn profiles",
		usesRadius: true,
		modules:    []string{"tun"},
		daemons:    []string{"openvpn"},
		// /etc/openvpn itself is the DISTRO package's directory and is deliberately
		// NOT listed; only what the panel creates inside it is removed. "server" is
		// the plain subdir the panel makes, which "server-*" does not match.
		//
		// Except that on Debian, Ubuntu and Fedora /etc/openvpn/server is the DISTRO's
		// server-config directory too, and the panel only mkdir's it and writes
		// nothing inside, so removing it could only ever destroy someone else's
		// configs. Uninstall now asks the ownership manifest, which knows whether that
		// mkdir actually created it.
		globs: []string{"/etc/openvpn/server-*", "/etc/openvpn/server", "/var/run/openvpn"},
	},
	{
		name: "openconnect", title: "OpenConnect (cisco)", backend: "ocserv",
		desc:       "AnyConnect-compatible TLS VPN",
		usesRadius: true,
		modules:    []string{"tun"},
		daemons:    []string{"ocserv", "ocserv-worker", "occtl"},
		// The config ROOT as well as the per-inbound files: a full uninstall that
		// left /etc/ocserv behind meant a later reinstall silently re-adopted the
		// old certificates and ocserv.conf.
		//
		// Listing the root here is now a REQUEST, not a licence. It used to be an
		// unconditional os.RemoveAll, which on a host with a distro ocserv deleted
		// that ocserv's ocserv.conf, its certificates and its ocpasswd. Uninstall
		// asks the ownership manifest, so the root only goes when we created it.
		paths: []string{"/etc/ocserv"},
		globs: []string{"/etc/ocserv/server-*", "/var/run/ocserv"},
	},
	{
		name: "sstp", title: "SSTP", backend: "accel-ppp",
		desc:       "Microsoft SSTP over HTTPS, native on Windows",
		usesRadius: true,
		modules:    []string{"ppp_generic"},
		feats:      []string{featAccel},
		// The config ROOT as well as the per-inbound files: a glob alone leaves the
		// directory behind once the last inbound is gone.
		paths: []string{"/etc/vpn-ui-sstp"},
		globs: []string{"/etc/vpn-ui-sstp/server-*"},
	},
	{
		name: "ikev2", title: "IKEv2", backend: "strongSwan (charon)",
		desc:       "IKEv2/IPsec, native on Windows, macOS, iOS and Android",
		usesRadius: true,
		optModules: []string{"af_key", "esp4", "xfrm_user"},
		feats:      []string{featStrongswan},
		// /etc/vpn-ui-ikev2 is deliberately NOT here. Despite the name it is the
		// SHARED charon config root: writeCharonConf() creates it whenever charon
		// is needed by either protocol, so an L2TP-only box has one too. Removing
		// it with IKEv2 would delete a directory L2TP still uses (and it would be
		// recreated on the next reload anyway). It goes with featStrongswan.
		globs: []string{"/etc/swanctl/conf.d/ikev2-*.conf"},
	},
	{
		name: "wgc", title: "WireGuard (C)", backend: "WireGuard (kernel)",
		desc:       "Kernel WireGuard",
		optModules: []string{"wireguard"},
	},
	{
		name: "awg", title: "AmneziaWG", backend: "AmneziaWG (kernel)",
		desc:       "WireGuard with obfuscated handshakes, built on this host via DKMS",
		optModules: []string{amneziawgModule},
		feats:      []string{featAmneziawg},
	},
	{
		name: "gre", title: "GRE", backend: "GRE (kernel)",
		desc: "Site-to-site router tunnels, optionally wrapped in IPsec",
		// ip_gre is already a REQUIRED module for PPTP, so it is not repeated here; fou
		// backs the optional UDP encapsulation and is absent on some minimal kernels.
		optModules: []string{greFouModule},
		// The IPsec mode rides the shared charon, so its connection files go with GRE while
		// featStrongswan itself stays (L2TP/IKEv2 may still need it) - same reference-counted
		// arrangement as the IKEv2 entry above.
		globs: []string{"/etc/swanctl/conf.d/gre-*.conf"},
	},
	{
		name: "mtproto", title: "MTProto Proxy", backend: "telemt",
		desc:    "Telegram MTProto proxy",
		daemons: []string{"telemt"},
		// See the SSTP entry: the root goes too.
		paths: []string{"/etc/vpn-ui-mtproto"},
		globs: []string{"/etc/vpn-ui-mtproto/server-*"},
	},
	{
		name: "ssh", title: "SSH", backend: "Built-in (pro-ui)",
		desc: "SSH tunnel gateway, served by the panel itself", builtin: true,
	},
	{
		name: "xray", title: "Xray", backend: "Xray-core",
		desc: "The Xray data plane every other core routes through", builtin: true,
	},
	{
		name: "radius", title: "RADIUS", backend: "Built-in (pro-ui)",
		desc: "Authentication for the dial-in protocols, served by the panel itself", builtin: true,
	},
}

// globalModules are needed no matter which cores are installed: every protocol's
// traffic is steered into Xray with TPROXY, so its module is part of the data
// plane rather than of any one core.
var globalModules = []string{"nf_tproxy_ipv4"}

// coreSpecFor returns the catalog row for a core name, or nil.
func coreSpecFor(name string) *coreSpec {
	for i := range coreCatalog {
		if coreCatalog[i].name == name {
			return &coreCatalog[i]
		}
	}
	return nil
}

// installableCores are the cores an operator can choose to install: everything
// in the catalog that actually needs something from the host. Built-in cores are
// excluded because there is nothing to install or remove.
func installableCores() []string {
	var out []string
	for _, c := range coreCatalog {
		if !c.builtin {
			out = append(out, c.name)
		}
	}
	return out
}

// specsFor resolves names to catalog rows, skipping unknown and built-in ones so
// a stale name from an older panel cannot make provisioning act on nothing.
func specsFor(names []string) []*coreSpec {
	seen := map[string]bool{}
	var out []*coreSpec
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if c := coreSpecFor(n); c != nil && !c.builtin {
			out = append(out, c)
		}
	}
	return out
}

// dedupe returns xs with duplicates removed, order preserved.
func dedupe(xs []string) []string {
	seen := make(map[string]bool, len(xs))
	out := xs[:0:0]
	for _, x := range xs {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// requiredModulesFor is the modules the given cores cannot run without, plus the
// globally required ones. Always non-empty: the TPROXY module is needed even by
// a selection of none.
func requiredModulesFor(names []string) []string {
	out := append([]string{}, globalModules...)
	for _, c := range specsFor(names) {
		out = append(out, c.modules...)
	}
	return dedupe(out)
}

// optionalModulesFor is the modules the given cores use where the kernel ships
// them and degrade without.
func optionalModulesFor(names []string) []string {
	var out []string
	for _, c := range specsFor(names) {
		out = append(out, c.optModules...)
	}
	return dedupe(out)
}

// daemonsFor is the bundled binaries the given cores need on disk.
func daemonsFor(names []string) []string {
	var out []string
	for _, c := range specsFor(names) {
		out = append(out, c.daemons...)
	}
	return dedupe(out)
}

// coresForDaemons maps bundled daemon names back to the cores that own them, so
// an error about missing daemons can name the protocols the operator actually
// picked rather than the raw binaries. Cores with no daemons are never listed.
func coresForDaemons(names []string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []string
	for _, c := range coreCatalog {
		if c.builtin {
			continue
		}
		for _, d := range c.daemons {
			if want[d] {
				out = append(out, c.name)
				break
			}
		}
	}
	return out
}

// needsFeature reports whether any of the given cores requires a feature. This
// is the whole of the shared-requirement logic: ask it about the cores being
// installed to decide whether to run a step, and about the cores that REMAIN to
// decide whether an uninstall may undo one.
func needsFeature(names []string, feat string) bool {
	for _, c := range specsFor(names) {
		for _, f := range c.feats {
			if f == feat {
				return true
			}
		}
	}
	return false
}

// anyCoreUsesRadius reports whether any of the given cores authenticates against
// the in-binary RADIUS server. Asked of the INSTALLED set, it is the whole of
// "does this host have a reason to run RADIUS".
func anyCoreUsesRadius(names []string) bool {
	for _, c := range specsFor(names) {
		if c.usesRadius {
			return true
		}
	}
	return false
}

// sharersOf lists the other installable cores that claim at least one feature
// with the named core. The setup UI shows this so "removing IKEv2 will not take
// IPsec away from L2TP" is visible before the operator commits, rather than
// something they have to trust silently happened.
func sharersOf(name string) []string {
	c := coreSpecFor(name)
	if c == nil || len(c.feats) == 0 {
		return nil
	}
	var out []string
	for i := range coreCatalog {
		other := &coreCatalog[i]
		if other.builtin || other.name == name {
			continue
		}
		if sharesAnyFeature(c, other) {
			out = append(out, other.name)
		}
	}
	sort.Strings(out)
	return out
}

func sharesAnyFeature(a, b *coreSpec) bool {
	for _, fa := range a.feats {
		for _, fb := range b.feats {
			if fa == fb {
				return true
			}
		}
	}
	return false
}

// CoreOption is one row of the setup dialog's core picker.
type CoreOption struct {
	Name      string `json:"name"`
	Title     string `json:"title"`
	Backend   string `json:"backend"`
	Desc      string `json:"desc"`
	Installed bool   `json:"installed"`
	// Inbounds is how many inbounds currently use this core. Non-zero blocks an
	// uninstall: pulling the daemon out from under live inbounds would leave
	// them configured but unserviceable.
	Inbounds int `json:"inbounds"`
	// Shares names the cores this one shares host requirements with, so the
	// dialog can say what an uninstall will deliberately leave behind.
	Shares []string `json:"shares,omitempty"`
	// Conflicts is what is ALREADY on this host that installing this core would
	// share: a distro daemon's config we would overwrite, a unit we would disable,
	// an interface of the operator's that shares our naming space. Nothing here
	// blocks an install; it is shown so taking over a running xl2tpd (or living
	// beside a hand-made GRE tunnel) is a decision rather than a surprise. See
	// preflight.go.
	Conflicts []coreHostConflict `json:"conflicts,omitempty"`
	// Builtin cores are listed for completeness but cannot be installed or
	// removed; the dialog renders them as always-on.
	Builtin bool `json:"builtin"`
}

// coreShouldProbeConflicts decides whether to run the pre-flight host probe for
// one core. Extracted from CoreCatalog so the rule can be pinned by a test
// without a host that happens to have the right daemons on it.
//
// `recorded` is coreInstallStateIsRecorded: did the panel WRITE DOWN this install
// state, or infer it. The `!recorded` term is the fix for a real hole. The old
// rule was `!builtin && !installed`, and with nothing recorded `installed` is the
// frozen baseline GUESS, which fires from a distro openvpn on PATH plus
// ip_forward=1. So on a fresh database the four baseline cores answered
// installed=true, the probe was skipped, and the operator was never warned about
// the distro xl2tpd, pptpd, libreswan and OpenVPN configs the panel was about to
// take over. Nothing has been provisioned, so nothing on that host is ours to be
// quiet about.
func coreShouldProbeConflicts(builtin, installed, recorded bool) bool {
	if builtin {
		return false // nothing to install, so nothing to collide with
	}
	return !recorded || !installed
}

// CoreCatalog returns every core with its current install state, for the setup
// and uninstall dialogs.
func (s *CoreService) CoreCatalog() []CoreOption {
	installed := s.provisionedProtocolSet()
	counts := s.inboundCountsByCore()
	// Whether those "installed" answers are RECORDED or GUESSED. Read once: it is
	// two setting lookups and the loop below asks it per core.
	recorded := s.coreInstallStateIsRecorded()

	out := make([]CoreOption, 0, len(coreCatalog))
	for _, c := range coreCatalog {
		opt := CoreOption{
			Name:      c.name,
			Title:     c.title,
			Backend:   c.backend,
			Desc:      c.desc,
			Installed: c.builtin || installed[c.name],
			Inbounds:  counts[c.name],
			Shares:    sharersOf(c.name),
			Builtin:   c.builtin,
		}
		// Probed for a core the operator can still choose to install: once it really
		// is installed the artifacts are ours and the manifest is the record that
		// matters. "Really" is the load-bearing word; see coreShouldProbeConflicts.
		if coreShouldProbeConflicts(c.builtin, installed[c.name], recorded) {
			opt.Conflicts = coreConflictProbe(c.name)
		}
		out = append(out, opt)
	}
	return out
}

// inboundCountsByCore counts the inbounds each core currently serves. It reuses
// the same per-service getters the status cards use, so the two can never
// disagree about whether a core is in use.
func (s *CoreService) inboundCountsByCore() map[string]int {
	counts := map[string]int{}
	add := func(name string, n int, err error) {
		if err == nil {
			counts[name] = n
		}
	}
	l2tp, err := s.l2tpService.GetL2tpInbounds()
	add("l2tp", len(l2tp), err)
	pptp, err := s.pptpService.GetPptpInbounds()
	add("pptp", len(pptp), err)
	ovpn, err := s.openvpnService.GetOpenVpnInbounds()
	add("openvpn", len(ovpn), err)
	oc, err := s.ocservService.GetOcservInbounds()
	add("openconnect", len(oc), err)
	sstp, err := s.sstpService.GetSstpInbounds()
	add("sstp", len(sstp), err)
	ike, err := s.ikev2Service.GetIkev2Inbounds()
	add("ikev2", len(ike), err)
	wgc, err := s.wgcService.GetWgcInbounds()
	add("wgc", len(wgc), err)
	awg, err := s.awgService.GetAwgInbounds()
	add("awg", len(awg), err)
	gre, err := s.greService.GetGreInbounds()
	add("gre", len(gre), err)
	mt, err := s.mtprotoService.GetMtprotoInbounds()
	add("mtproto", len(mt), err)
	ssh, err := s.sshService.GetSshInbounds()
	add("ssh", len(ssh), err)
	return counts
}

// installedCoreNames is the set of cores this host is provisioned for, in
// catalog order.
func (s *CoreService) installedCoreNames() []string {
	return coreNamesFromSet(s.provisionedProtocolSet())
}

// coreNamesFromSet is installedCoreNames over an already-read set, so a caller
// that needs both the set and the list does not re-read the setting twice.
func coreNamesFromSet(set map[string]bool) []string {
	var out []string
	for _, c := range coreCatalog {
		if !c.builtin && set[c.name] {
			out = append(out, c.name)
		}
	}
	return out
}

// protocolCoreName maps an inbound protocol to the core that serves it, or ""
// for the Xray-native protocols, which need no separate core. Only "wg-c"
// differs from its core name; the rest are identical, and the map is the single
// place that has to know it.
func protocolCoreName(protocol string) string {
	switch protocol {
	case "wg-c":
		return "wgc"
	}
	if c := coreSpecFor(protocol); c != nil && !c.builtin {
		return c.name
	}
	return ""
}

// validCoreNames filters a caller-supplied selection down to real, installable
// core names. Anything else (a typo, a built-in core, a name from a newer panel)
// is dropped rather than failing the request: a selection is a request to
// install what is understood, not a schema to validate.
func validCoreNames(names []string) []string {
	var out []string
	for _, c := range specsFor(names) {
		out = append(out, c.name)
	}
	return out
}

// orderedCoreNames normalises a core-name set into catalog order with duplicates
// removed, so the persisted list reads the same however it was assembled.
func orderedCoreNames(names []string) []string {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	var out []string
	for _, c := range coreCatalog {
		if !c.builtin && set[c.name] {
			out = append(out, c.name)
		}
	}
	return out
}

// RefreshInstalledDaemons re-extracts the bundled daemon binaries belonging to
// the cores this host has installed. The panel calls it on every start.
//
// The refresh exists so a panel upgrade actually delivers daemon fixes: the
// binaries used to be written only by one-time provisioning, so an
// already-provisioned host kept its original daemons forever and a new panel
// would write config an OLD daemon then silently misread. That refresh must NOT
// be the whole bundle, though, or per-core setup is a lie: every core would
// report itself installed on the next restart because "installed" is decided by
// the binary being on disk.
//
// Two cases have no recorded core set, and they need OPPOSITE answers:
//
//   - A host provisioned before per-core tracking existed. Its setup really did
//     install every daemon, so it gets the old whole-bundle refresh; anything
//     less would strand it on stale binaries, which is the bug this refresh was
//     added to fix.
//   - A brand new install that has never run setup at all. It must get NOTHING,
//     or the first panel start plants all nine daemons and every core reports
//     itself installed before the operator has chosen anything.
//
// vpnProvisioned tells them apart: the legacy host has it set, the fresh one
// does not.
func RefreshInstalledDaemons() ([]string, error) {
	var ss SettingService
	var cs CoreService
	if !ss.HasRecordedProvisionedProtocols() {
		if !cs.IsProvisioned() {
			return nil, nil // never set up: setup decides what lands on disk
		}
		return backend.Extract()
	}
	// ExtractOnly of an empty set extracts nothing, which is what a host with no
	// daemon-owning core installed should get.
	return backend.ExtractOnly(daemonsFor(cs.installedCoreNames()))
}

// bundledDaemonNames is every flat daemon binary the catalog knows about. Used
// to tell a daemon that belongs to some core from an unrelated file in BinDir
// (the Xray core and the geo files live there too and are never touched).
func bundledDaemonNames() []string {
	var out []string
	for _, d := range backend.Daemons {
		out = append(out, d.Name)
	}
	return out
}
