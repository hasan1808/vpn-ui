package service

import (
	"regexp"

	"github.com/vishvananda/netlink"
)

// Which kernel network interfaces are OURS.
//
// This is the fix for the most destructive bug in the project. The three
// daemon-less reconcilers (GRE, wg-c, AmneziaWG) garbage-collect the netdevs they
// no longer want, and each of them decided ownership with strings.HasPrefix:
//
//	gre.go  deleted any *netlink.Gretun whose name began "gre" and was not "gre0"
//	wgc.go  deleted ANY link whose name began "wgc", with no type check at all
//	awg.go  deleted ANY link whose name began "awg", with no type check at all
//
// An operator's own `ip tunnel add gre1 mode gre` matches the first rule exactly.
// So installing the GRE core was enough to destroy it: the sweep runs from panel
// start, from every inbound save, from every uninstall, and from the traffic job
// every ten seconds, so the operator's tunnel died within one tick and stayed
// dead however many times they recreated it. Nothing logged it, because from the
// panel's point of view it was collecting its own garbage.
//
// Ownership is now a POSITIVE test with three independent gates, all of which
// must pass before anything is deleted:
//
//  1. The name matches, anchored, the exact shape one of our generators emits.
//     Our names encode identity (gre<inbound>_<slot>_<peer>, wgc<inbound>) and no
//     human names a tunnel that way, which is what makes this safe on hosts that
//     already exist without renaming a single interface.
//  2. The link is of the kind that generator creates. wg-c and awg had no such
//     check, so a bridge, a veth or a dummy called "wgc0" was fair game.
//  3. The ownership manifest does not veto it. Manifest entries are what catch a
//     genuine collision (an operator whose device really is called "awg7"), and
//     they are recorded before we create anything; see ownership.go.
//
// Anything that fails a gate is simply skipped, exactly as an unrelated interface
// always was. The cost of being wrong is asymmetric: a leftover netdev of ours is
// a cosmetic wart, and someone else's deleted tunnel is an outage.

var (
	// greP2pNameRe matches greP2pName's normal form: gre<inboundID>_<slot>_<peerIdx>.
	greP2pNameRe = regexp.MustCompile(`^gre[0-9]+_[0-9]+_[0-9]+$`)
	// greP2pHashNameRe matches greP2pName's IFNAMSIZ overflow fallback: gre + the
	// FNV-32a of the long name, %08x. Deliberately fixed-width and lowercase-hex
	// only, so "gre1" and "gre0" cannot reach it.
	greP2pHashNameRe = regexp.MustCompile(`^gre[0-9a-f]{8}$`)
	// greCatNameRe matches greCatName: grecat + %04x of the local address hash.
	// Cannot overlap the two above: "cat" contains a non-hex letter and the width
	// is different.
	greCatNameRe = regexp.MustCompile(`^grecat[0-9a-f]{4}$`)
	// wgcNameRe / awgNameRe match wgIfaceName and awgIfaceName: the prefix plus the
	// inbound id, nothing else. "wgc-home", "wgc0x" and "awg_office" are theirs.
	wgcNameRe = regexp.MustCompile(`^wgc[0-9]+$`)
	awgNameRe = regexp.MustCompile(`^awg[0-9]+$`)

	// vpnOutCarrierNameRe matches vpnOutCarrierDev's normal form: xcar<8 hex>.
	vpnOutCarrierNameRe = regexp.MustCompile(`^xcar[0-9a-f]{8}$`)
)

// greOwnedName reports whether a netdev name has the exact shape GreService
// generates. It is the name half of the ownership test; greOwnsLink is the whole
// of it.
//
// gre0 is excluded by construction (the kernel's fallback device is a bare "gre0",
// which matches none of the three shapes) and is also checked explicitly at the
// call sites, because deleting it would break PPTP, which shares the module.
func greOwnedName(name string) bool {
	if name == "gre0" {
		return false
	}
	return greP2pNameRe.MatchString(name) ||
		greP2pHashNameRe.MatchString(name) ||
		greCatNameRe.MatchString(name)
}

func wgcOwnedName(name string) bool { return wgcNameRe.MatchString(name) }

func awgOwnedName(name string) bool { return awgNameRe.MatchString(name) }

// greOwnsLink is the full ownership test for a GRE netdev: our name shape, a real
// GRE tunnel device, and no manifest veto.
//
// The type assertion stays even though the name shape already rules out almost
// everything, because the two failure modes are independent: a name collision
// with a device of another kind (a bridge called "gre12345678") is exactly the
// case where deleting would be worst.
func greOwnsLink(l netlink.Link) bool {
	name := l.Attrs().Name
	if !greOwnedName(name) {
		return false
	}
	if _, ok := l.(*netlink.Gretun); !ok {
		return false
	}
	return !ownForbidsDelete(ownIface, name)
}

// wgcOwnsLink is the full ownership test for a wg-c netdev. The kind check is new:
// wgc.go deleted anything at all whose name started with "wgc".
func wgcOwnsLink(l netlink.Link) bool {
	name := l.Attrs().Name
	if !wgcOwnedName(name) {
		return false
	}
	if _, ok := l.(*netlink.Wireguard); !ok {
		return false
	}
	return !ownForbidsDelete(ownIface, name)
}

// vpnOutCarrierOwnedName reports whether a netdev name has the exact shape
// vpnoutcarrier.go generates: "xcar" plus eight hex digits of the carrier tag's hash.
// Anchored and fixed-width, so it cannot match a device somebody named "xcar" or
// "xcar0" by hand.
func vpnOutCarrierOwnedName(name string) bool { return vpnOutCarrierNameRe.MatchString(name) }

// vpnOutCarrierOwnsLink is the full ownership test for a carrier tun.
//
// The kind gate matters more here than for the other families, because this is the one
// device the panel creates that a person might plausibly also create: a tuntap is what
// every VPN client on earth makes. The name shape is what carries the identity, and the
// kind check stops a bridge or a dummy wearing the name from being deleted.
func vpnOutCarrierOwnsLink(l netlink.Link) bool {
	name := l.Attrs().Name
	if !vpnOutCarrierOwnedName(name) {
		return false
	}
	if _, ok := l.(*netlink.Tuntap); !ok {
		return false
	}
	return !ownForbidsDelete(ownIface, name)
}

// awgOwnsLink is the full ownership test for an AmneziaWG netdev. The module is
// out of tree, so the netlink library does not model it and the kernel hands it
// back as a GenericLink carrying the "amneziawg" kind.
func awgOwnsLink(l netlink.Link) bool {
	name := l.Attrs().Name
	if !awgOwnedName(name) {
		return false
	}
	if l.Type() != amneziawgLinkKind {
		return false
	}
	return !ownForbidsDelete(ownIface, name)
}

// ownIfaceCreated records a netdev we just created, so uninstall knows what to
// take away and a later ownership question has a positive record to consult.
func ownIfaceCreated(name, core string) { ownClaim(ownIface, name, core) }

// ownSynthesizeIfaces records every netdev already on the host that wears one of
// our generated name shapes, and is the reason an upgrade neither strands nor
// destroys anything. It runs once, from OwnSynthesize, before any Init* has
// created a thing.
//
// Two cases look identical from the outside and need opposite answers, and the
// installed-core set is what tells them apart:
//
//   - The core is ALREADY installed, so a netdev with our exact name shape is a
//     leftover from OUR previous run (netdevs survive a panel restart, they just
//     do not survive a reboot). Adopting it keeps the stale-link sweep working
//     across the upgrade.
//   - The core is NOT installed, so anything wearing our name shape got there some
//     other way, however unlikely the collision. It is recorded as pre-existing,
//     which vetoes every later delete.
func ownSynthesizeIfaces(installed map[string]bool) int {
	links, err := netlink.LinkList()
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range links {
		var core string
		switch {
		// The manifest veto inside the *OwnsLink helpers is irrelevant here (nothing
		// is recorded yet on this path), so these match on name shape plus link kind.
		case greOwnedName(l.Attrs().Name):
			if _, ok := l.(*netlink.Gretun); !ok {
				continue
			}
			core = "gre"
		case wgcOwnedName(l.Attrs().Name):
			if _, ok := l.(*netlink.Wireguard); !ok {
				continue
			}
			core = "wgc"
		case awgOwnedName(l.Attrs().Name):
			if l.Type() != amneziawgLinkKind {
				continue
			}
			core = "awg"
		case vpnOutCarrierOwnedName(l.Attrs().Name):
			if _, ok := l.(*netlink.Tuntap); !ok {
				continue
			}
			// Deliberately keyed on a core NOBODY installs, so a device wearing this
			// name shape on a host the panel has not made one on is recorded as
			// pre-existing and vetoed from every later delete. Carrier devices are not
			// a core: they are made on demand when a tunnel names an Xray outbound as
			// its carrier, so "is the core installed" has no answer for them and the
			// safe answer is the one that never deletes somebody else's tuntap.
			core = "vpnoutcarrier"
		default:
			continue
		}
		name := l.Attrs().Name
		if _, found := ownStateOf(ownIface, name); found {
			continue
		}
		if installed[core] {
			ownClaim(ownIface, name, core)
		} else {
			ownNote(ownIface, name, core, "existed before the "+core+" core was installed")
		}
		n++
	}
	return n
}
