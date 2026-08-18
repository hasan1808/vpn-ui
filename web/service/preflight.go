package service

import (
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
)

// Pre-flight detection: what is ALREADY on this host that installing a core will
// have to live beside.
//
// The ownership manifest makes install and uninstall non-destructive, but it does
// its work silently, and silence is the wrong answer when an operator is about to
// hand their machine's xl2tpd (or ocserv, or IPsec, or a GRE tunnel) over to the
// panel. This reports the collisions BEFORE they commit, so "the panel took over
// my VPN" is a decision they made rather than something they discover afterwards.
//
// Everything here is a stat, a unit query or a netlink list. No side effects, so
// it is safe to call from a GET that renders the setup dialog.

// coreHostConflict is one thing already on the host that a core would share.
type coreHostConflict struct {
	// Kind is one of the manifest's artifact kinds, so the dialog can group them.
	Kind string `json:"kind"`
	// What names the artifact (a path, a unit, an interface).
	What string `json:"what"`
	// Detail says what installing this core will do about it, in the operator's
	// terms rather than the manifest's.
	Detail string `json:"detail"`
}

// preflightFile reports a config file the named core will overwrite.
func preflightFile(path string) *coreHostConflict {
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	return &coreHostConflict{Kind: ownFile, What: path,
		Detail: "already present; vpn-ui will replace it and keep a copy in " + ownershipBackupDir}
}

// preflightDir reports a config directory the core will write into.
func preflightDir(path string) *coreHostConflict {
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() {
		return nil
	}
	return &coreHostConflict{Kind: ownDir, What: path,
		Detail: "already exists; vpn-ui will add its own files inside it and never remove the directory"}
}

// preflightUnit reports a distro service the panel will stop and disable so it
// can run that daemon itself.
func preflightUnit(unit string) *coreHostConflict {
	if !commandExists("systemctl") {
		return nil
	}
	enabled, active := unitEnabled(unit), unitActive(unit)
	if !enabled && !active {
		return nil
	}
	state := "enabled"
	if active && enabled {
		state = "enabled and running"
	} else if active {
		state = "running"
	}
	return &coreHostConflict{Kind: ownUnit, What: unit,
		Detail: state + "; vpn-ui will stop and disable it so the panel can run this daemon, and re-enable it on uninstall"}
}

// preflightIfaces reports the operator's own netdevs that share a protocol's
// naming space. These are NOT touched (see ifaceown.go), and saying so is the
// point: this is the exact case the user reported, where a hand-made GRE tunnel
// disappeared as soon as the GRE core was installed.
func preflightIfaces(core string) []coreHostConflict {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	var out []coreHostConflict
	for _, l := range links {
		name := l.Attrs().Name
		var match bool
		switch core {
		case "gre":
			_, isGre := l.(*netlink.Gretun)
			match = isGre && !greOwnedName(name)
		case "wgc":
			_, isWg := l.(*netlink.Wireguard)
			match = isWg && !wgcOwnedName(name)
		case "awg":
			match = l.Type() == amneziawgLinkKind && !awgOwnedName(name)
		}
		if !match {
			continue
		}
		out = append(out, coreHostConflict{Kind: ownIface, What: name,
			Detail: "your own interface; vpn-ui will not touch it"})
	}
	return out
}

// coreConflictProbe is hostConflictsFor behind a seam, so a test can substitute a
// probe over paths it controls. The real probe reads absolute host paths
// (/etc/ipsec.conf and friends), which a test can neither create nor rely on, and
// the question worth pinning is WHICH CORES get probed under which recorded
// install state rather than what a stat returns.
var coreConflictProbe = hostConflictsFor

// hostConflictsFor lists everything already on this host that installing one core
// would share. Empty for a core with nothing in its way, which is the normal case
// on a clean box.
func hostConflictsFor(core string) []coreHostConflict {
	var out []coreHostConflict
	add := func(c *coreHostConflict) {
		if c != nil {
			out = append(out, *c)
		}
	}

	switch core {
	case "l2tp":
		add(preflightFile("/etc/xl2tpd/xl2tpd.conf"))
		add(preflightFile("/etc/ppp/options.xl2tpd"))
		add(preflightFile("/etc/ipsec.conf"))
		add(preflightFile("/etc/ipsec.secrets"))
		add(preflightUnit("xl2tpd.service"))
		add(preflightUnit("ipsec.service"))
	case "pptp":
		add(preflightFile("/etc/pptpd.conf"))
		add(preflightFile("/etc/ppp/pptpd-options"))
		add(preflightUnit("pptpd.service"))
	case "openvpn":
		add(preflightDir("/etc/openvpn"))
		add(preflightDir("/etc/openvpn/server"))
		// openvpn-server@<name> is templated, so the instances are found rather
		// than named. An enabled instance is the operator's own server.
		if matches, _ := filepath.Glob("/etc/openvpn/server/*.conf"); len(matches) > 0 {
			out = append(out, coreHostConflict{Kind: ownFile, What: "/etc/openvpn/server/*.conf",
				Detail: "the distro's own OpenVPN server configs; vpn-ui neither reads nor removes them"})
		}
	case "openconnect":
		add(preflightDir("/etc/ocserv"))
		add(preflightFile("/etc/ocserv/ocserv.conf"))
		add(preflightUnit("ocserv.service"))
	case "sstp":
		add(preflightDir("/etc/accel-ppp"))
		add(preflightUnit("accel-ppp.service"))
	case "ikev2":
		add(preflightFile("/etc/strongswan.conf"))
		add(preflightFile("/etc/swanctl/swanctl.conf"))
		add(preflightDir("/etc/swanctl/conf.d"))
		add(preflightUnit("strongswan.service"))
		add(preflightUnit("ipsec.service"))
	case "gre", "wgc", "awg":
		out = append(out, preflightIfaces(core)...)
	}
	return out
}
