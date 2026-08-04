package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/goccy/go-json"
	"github.com/vishvananda/netlink"
)

// VPN protocols as OUTBOUNDS: the panel dials out as a CLIENT of somebody else's VPN
// server, the client brings up a netdev (wg/tun/ppp/gre/xfrm), and Xray egresses
// through it. The mirror image of the inbound side, where the panel is the server.
//
// The mechanism is a synthesized `freedom` outbound whose socket is pinned to that
// netdev with SO_BINDTODEVICE, which the shipped core exposes as
// `streamSettings.sockopt.interface` (transport/internet/sockopt_linux.go). Same
// shape as the SSH outbound facade in sshoutbound.go: the operator picks "l2tp" in
// the outbound modal, and what reaches Xray is an ordinary tagged outbound, so
// routing and reverse target it by tag with no special-casing anywhere.
//
// NOT Xray's `tun` proxy, which cannot do this. It is registered only as an INBOUND
// (infra/conf/xray.go registers "tun" in inboundConfigLoader and not in
// outboundConfigLoader) and its Handler implements proxy.Inbound alone. Its one
// interface-binding facility, autoOutboundsInterface, installs a PROCESS-GLOBAL
// dialer controller that would pin every outbound in the core to one device rather
// than just this one, so it cannot express "this tag goes through that tunnel".

// VpnOutboundKind names a client-side tunnel implementation. The value is stored, so
// these strings are wire format: rename one and every saved outbound of that kind
// stops resolving to a driver.
const (
	VpnOutWireguard   = "wireguard"
	VpnOutAmneziaWG   = "awg"
	VpnOutGre         = "gre"
	VpnOutOpenVPN     = "openvpn"
	VpnOutL2TP        = "l2tp"
	VpnOutIKEv2       = "ikev2"
	VpnOutPPTP        = "pptp"
	VpnOutOpenConnect = "openconnect"
	VpnOutSSTP        = "sstp"
)

// VpnOutboundConfig is one client tunnel as stored in the `vpnOutbounds` setting.
//
// Settings is per-protocol and stays opaque here on purpose: the framework owns the
// lifecycle and the Xray synthesis, and knows nothing about PSKs, keypairs or cipher
// lists. Each driver unmarshals its own shape out of it, which is what lets a new
// protocol land as one new file.
type VpnOutboundConfig struct {
	Tag    string `json:"tag" form:"tag"`
	Kind   string `json:"kind" form:"kind"`
	Remark string `json:"remark" form:"remark"`
	Enable bool   `json:"enable" form:"enable"`

	// Iface is the netdev the driver brought up and the one the synthesized outbound
	// binds to. Written by the driver, never by the operator: a name typed into the
	// panel would be a promise about the kernel that nothing checks, and a wrong one
	// binds egress to some other interface that happens to exist.
	Iface string `json:"iface"`

	Settings json.RawMessage `json:"settings" form:"settings"`
}

// VpnOutDriver is what a protocol implements to become an outbound. One file per
// protocol, registered from its own init(), so protocols can be added without any
// two of them editing the same line.
type VpnOutDriver interface {
	// Up brings the client tunnel up and returns the name of the netdev Xray should
	// bind egress to. Must be idempotent: it is called on save, on panel boot, and
	// by the reconciler, and the second call on an already-up tunnel has to return
	// the same interface rather than churn it.
	Up(cfg VpnOutboundConfig) (iface string, err error)

	// Down tears it back down. Must tolerate being called on a tunnel that is
	// already down, which is what happens when the panel restarts between a failed
	// Up and the next reconcile.
	Down(cfg VpnOutboundConfig) error

	// Status reports whether the tunnel is carrying traffic, plus one line of detail
	// for the panel (peer address, last handshake, negotiated address).
	Status(cfg VpnOutboundConfig) (up bool, detail string)

	// Validate rejects a config the operator is about to save, before anything is
	// brought up. Returning an error here is how a driver refuses a missing key or
	// an unroutable endpoint while the modal is still open.
	Validate(cfg VpnOutboundConfig) error
}

// VpnOutAvailability is an OPTIONAL interface a driver may also implement when it
// depends on something that can be absent from a given host: a bundled client binary
// that was never built for this arch, or a kernel module that is not loaded.
//
// It exists because //go:embed uses `all:bin`, so a binary missing from the bundle is
// a RUNTIME failure rather than a build one. Without this, an outbound whose client
// was never bundled is offered in the picker, accepted on save, and then fails when
// it is raised, which reads as a broken panel rather than a missing dependency.
//
// A driver that is always usable simply does not implement it.
type VpnOutAvailability interface {
	// Available reports whether this driver can work here, and if not, one line
	// saying what is missing, written for an operator rather than a log.
	Available() (bool, string)
}

// vpnOutAvailable answers for any driver, including the ones that do not implement
// the optional interface.
func vpnOutAvailable(d VpnOutDriver) (bool, string) {
	if a, ok := d.(VpnOutAvailability); ok {
		return a.Available()
	}
	return true, ""
}

// VpnOutKindAvailable reports whether a protocol can actually be used on this host.
// The panel calls it to explain a greyed-out entry rather than silently omitting one.
func VpnOutKindAvailable(kind string) (bool, string) {
	d, err := vpnOutDriverFor(kind)
	if err != nil {
		return false, err.Error()
	}
	return vpnOutAvailable(d)
}

// vpnOutDrivers is the kind -> implementation registry, populated from each driver
// file's init(). Guarded because tests register fakes after startup; the init()s
// themselves are single-threaded.
var (
	vpnOutDriverMu sync.RWMutex
	vpnOutDrivers  = map[string]VpnOutDriver{}
)

// RegisterVpnOutDriver wires a protocol into the outbound framework. Called from the
// driver's own init(). Panics on a duplicate kind, which is a build-time mistake
// (two files claiming one protocol) and not something to discover at runtime.
func RegisterVpnOutDriver(kind string, d VpnOutDriver) {
	vpnOutDriverMu.Lock()
	defer vpnOutDriverMu.Unlock()
	if _, dup := vpnOutDrivers[kind]; dup {
		panic("vpn outbound: duplicate driver for kind " + kind)
	}
	vpnOutDrivers[kind] = d
}

// VpnOutKinds lists the registered protocols, sorted, for the panel's picker. Built
// from the registry rather than a hand-kept list so a protocol whose driver failed
// to compile in cannot be offered in the UI.
func VpnOutKinds() []string {
	vpnOutDriverMu.RLock()
	defer vpnOutDriverMu.RUnlock()
	out := make([]string, 0, len(vpnOutDrivers))
	for k := range vpnOutDrivers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func vpnOutDriverFor(kind string) (VpnOutDriver, error) {
	vpnOutDriverMu.RLock()
	defer vpnOutDriverMu.RUnlock()
	d, ok := vpnOutDrivers[kind]
	if !ok {
		return nil, fmt.Errorf("no outbound driver for protocol %q", kind)
	}
	return d, nil
}

const vpnOutboundsSettingKey = "vpnOutbounds"

// vpnOutCfgMu serialises the read-modify-write of the whole list, which lives in ONE
// settings row. Same hazard sshoutbound.go documents: without it two concurrent
// saves both load the same list, both append, and the loser's tunnel disappears from
// the setting while its netdev stays up with nothing tracking it.
var vpnOutCfgMu sync.Mutex

// VpnOutboundService is the panel-facing API. Stateless; the live tunnels belong to
// their drivers, which own whatever kernel or daemon state each protocol needs.
type VpnOutboundService struct{}

// InitVpnOutbound raises every enabled tunnel at panel boot, and records the device
// each one actually landed on.
//
// The lock spans the raises for the same reason Save's does: what is written back is
// derived from what was read, so a save landing in between would be merged away.
func (s *VpnOutboundService) InitVpnOutbound() {
	vpnOutCfgMu.Lock()
	defer vpnOutCfgMu.Unlock()

	all := s.load()
	moved := false
	for i, cfg := range all {
		if !cfg.Enable {
			continue
		}
		iface, err := s.bringUp(cfg)
		if err != nil {
			// Best effort, exactly as the inbound daemons are at boot: one
			// unreachable peer must not stop the panel coming up, and the outbound
			// reports itself down in the UI where it can be retried.
			logger.Warning("vpn outbound: could not raise", cfg.Tag, "("+cfg.Kind+"):", err)
			continue
		}
		// The device is RECORDED, not discarded. A ppp driver hands back the live
		// interface rather than the one it asked for (pppd's rename is best effort),
		// so a tunnel can come back on a different pppN across a reboot. Dropping that
		// left the synthesized outbound pinned to the previous name for the whole run,
		// which either fails every connection through the tunnel or, worse, binds this
		// tunnel's egress to whatever else has taken the name since.
		if iface != all[i].Iface {
			all[i].Iface = iface
			moved = true
		}
	}
	if moved {
		if err := s.persist(all); err != nil {
			logger.Warning("vpn outbound: could not record the interfaces the tunnels came up on:", err)
		}
	}
}

// VpnOutSecrets is an OPTIONAL interface naming the settings keys that must never
// leave the server: private keys, PPP passwords, a pasted .ovpn or wg config.
//
// Declared by the driver rather than guessed by the framework, because a name list
// held out here cannot be right. A driver that stores its whole profile under one
// key ("conf" holding a wg config with PrivateKey= inside it) defeats any guess at
// secret-looking names, while the endpoint would go on claiming it masks. The
// protocol that chose the shape is the only thing that knows which keys are hot.
//
// Whole keys are REMOVED rather than blanked, which is what makes editing survive:
// Save treats an absent key as "keep the stored value" (see mergeKeptSettings), so a
// masked list round-trips through the panel without the operator re-pasting a key to
// change an MTU. Blanking to "" would instead be a present-and-empty value, and the
// first save would wipe the secret.
type VpnOutSecrets interface {
	SecretKeys() []string
}

// List returns the configured tunnels with every driver-declared secret stripped.
// This is what the panel sees.
//
// Callers that need the REAL settings must use listRaw. The distinction matters:
// charon.go decides whether to keep the shared IPsec daemon alive by looking for an
// L2TP tunnel's psk, and reading that through this method would find a masked blob,
// answer "no IPsec outbound" and stop charon under a live tunnel.
func (s *VpnOutboundService) List() []VpnOutboundConfig {
	all := s.listRaw()
	out := make([]VpnOutboundConfig, len(all))
	for i, c := range all {
		c.Settings = maskVpnOutSecrets(c.Kind, c.Settings)
		out[i] = c
	}
	return out
}

// listRaw returns the tunnels as stored, secrets included. Internal only.
func (s *VpnOutboundService) listRaw() []VpnOutboundConfig { return s.load() }

// maskVpnOutSecrets drops a driver's declared secret keys from one settings blob.
// A blob that will not parse is replaced outright rather than passed through: it
// cannot be masked key by key, and shipping an unmaskable blob to the browser is the
// failure this exists to prevent.
func maskVpnOutSecrets(kind string, settings json.RawMessage) json.RawMessage {
	if len(settings) == 0 {
		return settings
	}
	drv, err := vpnOutDriverFor(kind)
	if err != nil {
		return nil
	}
	sec, ok := drv.(VpnOutSecrets)
	if !ok {
		return settings
	}
	keys := sec.SecretKeys()
	if len(keys) == 0 {
		return settings
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(settings, &obj); err != nil {
		return nil
	}
	for _, k := range keys {
		delete(obj, k)
	}
	masked, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return masked
}

// mergeKeptSettings folds a stored settings blob into an incoming one: a key the
// caller did not send keeps whatever was stored. Present wins, including an
// explicitly empty value, which is how a secret is deliberately cleared.
//
// This is the other half of masking. The panel never receives a secret, so it cannot
// send one back, and without this every save of an existing tunnel would fail its
// driver's Validate for a missing key the server has had all along. The same shape
// SshOutboundService.Save gets from its three `if cfg.X == "" { cfg.X = prev.X }`
// lines, generalised, because Settings is opaque here and cannot be merged field by
// field.
//
// Top level only. A nested object arrives as one value and replaces wholesale, which
// is the conservative reading: a half-merged nested profile is harder to reason about
// than one the operator resends.
func mergeKeptSettings(incoming, stored json.RawMessage) json.RawMessage {
	if len(stored) == 0 {
		return incoming
	}
	if len(incoming) == 0 {
		return stored
	}
	var in, old map[string]json.RawMessage
	if json.Unmarshal(incoming, &in) != nil || json.Unmarshal(stored, &old) != nil {
		// Not both objects, so there is no key-level merge to do. The caller's value
		// stands, which is the same answer as having no stored value at all.
		return incoming
	}
	for k, v := range old {
		if _, sent := in[k]; !sent {
			in[k] = v
		}
	}
	merged, err := json.Marshal(in)
	if err != nil {
		return incoming
	}
	return merged
}

// Save upserts a tunnel by tag, brings it up, and records the interface it landed on.
//
// Brought up BEFORE the config is persisted, because bringing it up is what decides
// the interface name, and that name is what the synthesized outbound binds to. The
// same ordering as SshOutboundService.Save and for the same reason: choosing the
// value first and hoping the kernel agrees is the version with a race in it.
func (s *VpnOutboundService) Save(cfg VpnOutboundConfig) (VpnOutboundConfig, error) {
	cfg.Tag = strings.TrimSpace(cfg.Tag)
	cfg.Kind = strings.TrimSpace(cfg.Kind)
	if cfg.Tag == "" {
		return cfg, errors.New("tag is required")
	}
	// A tag collision would have the synthesized outbound quietly replace an
	// operator's hand-written one of the same name; refuse instead.
	if strings.ContainsAny(cfg.Tag, " \t\r\n") {
		return cfg, errors.New("tag cannot contain spaces")
	}
	drv, err := vpnOutDriverFor(cfg.Kind)
	if err != nil {
		return cfg, err
	}
	// Refused at save rather than at raise. A tunnel whose client is not on this host
	// can never work, and storing it would leave an outbound in the list that fails
	// every boot with a message nobody is watching for.
	if ok, why := vpnOutAvailable(drv); !ok {
		return cfg, fmt.Errorf("%s outbounds are not available on this host: %s", cfg.Kind, why)
	}
	// The lock is taken BEFORE the stored settings are read, not after. The merge
	// below decides what is written from what is currently there, so reading outside
	// the lock and writing inside it lets two admins saving the same tunnel at the
	// same instant merge against a value the other has already replaced.
	vpnOutCfgMu.Lock()
	defer vpnOutCfgMu.Unlock()

	all := s.load()

	// Restore whatever the caller could not send back before anything validates.
	// The panel is served a masked list, so an edit posts no private key at all;
	// validating first would reject every edit of an existing tunnel for a secret
	// the server has had the whole time. Skipped across a kind change, where the
	// stored settings belong to a different protocol's shape entirely.
	if prev, ok := findVpnTunnel(all, cfg.Tag); ok && prev.Kind == cfg.Kind {
		cfg.Settings = mergeKeptSettings(cfg.Settings, prev.Settings)
	}

	if err := drv.Validate(cfg); err != nil {
		return cfg, err
	}

	out := make([]VpnOutboundConfig, 0, len(all)+1)
	for _, c := range all {
		if c.Tag == cfg.Tag {
			// Changing an existing tunnel's protocol leaves the old driver's netdev
			// behind, and only the old driver knows how to remove it.
			if c.Kind != cfg.Kind {
				if old, err := vpnOutDriverFor(c.Kind); err == nil {
					vpnOutUnbindEgress(c.Iface)
					if err := old.Down(c); err != nil {
						logger.Warning("vpn outbound: could not tear down the previous",
							c.Kind, "tunnel for", c.Tag, ":", err)
					}
				}
			}
			continue // replaced below
		}
		out = append(out, c)
	}

	if cfg.Enable {
		iface, err := s.bringUp(cfg)
		if err != nil {
			return cfg, err
		}
		cfg.Iface = iface
	} else {
		// Saved disabled: take it down and forget the interface, so the synthesized
		// outbound is dropped rather than left bound to a device that is gone.
		vpnOutUnbindEgress(cfg.Iface)
		if err := drv.Down(cfg); err != nil {
			logger.Warning("vpn outbound: could not stop", cfg.Tag, ":", err)
		}
		cfg.Iface = ""
	}

	out = append(out, cfg)
	if err := s.persist(out); err != nil {
		// Up but unrecorded: the next restart would not raise it, and the caller is
		// about to point an outbound at an interface nothing re-creates.
		if cfg.Enable {
			vpnOutUnbindEgress(cfg.Iface)
			_ = drv.Down(cfg)
		}
		return cfg, err
	}
	// The freedom outbound fronting this tunnel is derived from the stored list when
	// the config is built, so the core has to be rebuilt for the change to reach it.
	(&XrayService{}).SetToNeedRestart()
	return cfg, nil
}

// Delete removes a tunnel by tag and tears it down.
func (s *VpnOutboundService) Delete(tag string) error {
	vpnOutCfgMu.Lock()
	defer vpnOutCfgMu.Unlock()

	all := s.load()
	out := make([]VpnOutboundConfig, 0, len(all))
	var victim *VpnOutboundConfig
	for i, c := range all {
		if c.Tag == tag {
			victim = &all[i]
			continue
		}
		out = append(out, c)
	}
	if victim == nil {
		return nil
	}
	if err := s.persist(out); err != nil {
		return err
	}
	if drv, err := vpnOutDriverFor(victim.Kind); err == nil {
		vpnOutUnbindEgress(victim.Iface)
		if err := drv.Down(*victim); err != nil {
			logger.Warning("vpn outbound: could not stop", tag, "on delete:", err)
		}
	}
	(&XrayService{}).SetToNeedRestart()
	return nil
}

// Status reports one tunnel's live state.
func (s *VpnOutboundService) Status(tag string) (bool, string) {
	for _, c := range s.load() {
		if c.Tag != tag {
			continue
		}
		if !c.Enable {
			return false, "disabled"
		}
		drv, err := vpnOutDriverFor(c.Kind)
		if err != nil {
			return false, err.Error()
		}
		return drv.Status(c)
	}
	return false, "no such outbound"
}

// StopAll tears every tunnel down, for panel shutdown.
func (s *VpnOutboundService) StopAll() {
	for _, c := range s.load() {
		if drv, err := vpnOutDriverFor(c.Kind); err == nil {
			vpnOutUnbindEgress(c.Iface)
			if err := drv.Down(c); err != nil {
				logger.Warning("vpn outbound: could not stop", c.Tag, "on shutdown:", err)
			}
		}
	}
}

// bringUp runs the driver and insists it names an interface. A driver that reports
// success without one would produce a freedom outbound bound to "", which is not an
// error to Xray: it is an unbound socket, so the tunnel silently does nothing and
// every byte leaves through the host's own default route instead. That failure is
// invisible from the panel and looks exactly like a working outbound, so it is
// caught here rather than shipped.
func (s *VpnOutboundService) bringUp(cfg VpnOutboundConfig) (string, error) {
	drv, err := vpnOutDriverFor(cfg.Kind)
	if err != nil {
		return "", err
	}
	iface, err := drv.Up(cfg)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(iface) == "" {
		return "", fmt.Errorf("the %s client came up without naming an interface", cfg.Kind)
	}
	// Done here rather than in each driver because every protocol needs exactly the
	// same thing, and eight copies of a routing scheme is eight chances to pick a
	// colliding table number.
	if err := vpnOutBindEgress(iface); err != nil {
		// The interface is up but nothing can egress through it, which would present
		// as an outbound that exists and silently fails every connection. Take it
		// back down rather than hand back a tunnel that cannot work.
		_ = drv.Down(cfg)
		return "", err
	}
	return iface, nil
}

// Egress routing for a pinned socket.
//
// SO_BINDTODEVICE is not on its own enough to send a packet. It sets flowi4_oif, and
// the FIB lookup then skips every route whose nexthop device is not this one: the
// host's `default ... dev eth0` stops matching, and a freshly created tunnel carries
// only its own on-link route. A freedom outbound pinned to it fails with
// ENETUNREACH for every destination off the tunnel subnet.
//
// So each tunnel needs a default route through its own device. It must NOT go in the
// main table: that is the whole host rerouted into somebody else's VPN, including the
// panel's own SSH session and its update checks. Instead each tunnel gets a private
// table selected by a rule that matches ONLY sockets already bound to that device, so
// nothing else on the box can reach it, and traffic that was not deliberately pinned
// is untouched.
const vpnOutRouteTableBase = 30000

// vpnOutBindEgress makes iface usable by sockets pinned to it. Idempotent, because
// Up is.
func vpnOutBindEgress(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("cannot find the interface %q the client just brought up: %w", iface, err)
	}
	table := vpnOutRouteTableBase + link.Attrs().Index

	// Reverse-path filtering has to be relaxed for the tunnel. A reply arriving here is
	// validated against a route that lives in the private table above, which the
	// reverse lookup does not consult (it has no oif to match the rule on), so strict
	// mode drops every inbound packet silently. gre.go does the same per interface for
	// the same reason.
	//
	// BOTH knobs, and that is the whole point: the kernel uses
	// MAX(conf.all.rp_filter, conf.<dev>.rp_filter), so setting the device to 0 on a
	// host whose `all` is strict leaves the effective value strict and relaxes nothing.
	// Setting only the device looks correct and silently does not work.
	vpnOutSetRPFilter(iface, 0)
	vpnOutRelaxHostRPFilter()

	// Recreating an interface moves its index, and the table id is derived from it, so
	// a rule left over from the previous incarnation points at a table that is now
	// empty. Left alone they accumulate one per rebuild. Swept before the current one
	// is added so the interface is only ever selected by one rule.
	vpnOutSweepRules(iface, table)

	// The rule names the device rather than its index: the kernel stores FRA_OIFNAME
	// and revalidates it as devices come and go, so a tunnel recreated with a
	// different ifindex keeps working. Matching on the index would leave a rule
	// pointing at whatever took the number next.
	rule := netlink.NewRule()
	rule.OifName = iface
	rule.Table = table
	// Priority == table id: unique per tunnel, and it makes the rule findable for
	// deletion without having to match every other field.
	rule.Priority = table
	rule.Family = netlink.FAMILY_V4
	if err := vpnOutEnsureRule(rule); err != nil {
		return fmt.Errorf("cannot route traffic pinned to %s: %w", iface, err)
	}

	// A plain `default dev X` with no nexthop, which is what a point-to-point device
	// wants. Every tunnel this framework raises is p2p or tun; a device that needed a
	// gateway would need this widened rather than worked around in its driver.
	//
	// 0.0.0.0/0 is written OUT rather than left as a nil Dst meaning "everything".
	// netlink refuses a route with no destination, no source and no gateway outright
	// ("either Dst.IP, Src.IP or Gw must be set", route_linux.go), before it builds
	// the message, so a nil Dst here never reached the kernel: it failed every raise
	// of every protocol, and bringUp took the tunnel back down and reported the
	// tunnel itself as unusable.
	def := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Table:     table,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Scope:     netlink.SCOPE_LINK,
	}
	if err := netlink.RouteReplace(def); err != nil {
		return fmt.Errorf("cannot install the egress route for %s: %w", iface, err)
	}
	return nil
}

// vpnOutUnbindEgress removes what vpnOutBindEgress installed. Best effort and quiet
// about a missing rule: the common path here is a teardown of something already half
// gone, and the kernel drops a device's routes with the device.
func vpnOutUnbindEgress(iface string) {
	if strings.TrimSpace(iface) == "" {
		return
	}
	// By name, not by the index we bound with. The device may already be gone, or back
	// with a different index, and either way the rule is the thing that must not
	// survive: a stale oif rule pointing at a recycled name would divert a later
	// tunnel's traffic into a table holding somebody else's route.
	//
	// Enumerated and matched rather than handed a template to RuleDel, because a
	// template carries zero values for every field it does not set and what those
	// match is not something to be guessing at during a teardown.
	vpnOutSweepRules(iface, 0)
	if link, err := netlink.LinkByName(iface); err == nil {
		table := vpnOutRouteTableBase + link.Attrs().Index
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
			&netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err == nil {
			for i := range routes {
				_ = netlink.RouteDel(&routes[i])
			}
		}
	}
}

// vpnOutEnsureRule adds a rule unless an equivalent one is already present. netlink
// happily installs a second identical rule, and every restart would add one more.
func vpnOutEnsureRule(want *netlink.Rule) error {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err == nil {
		for _, r := range rules {
			if r.OifName == want.OifName && r.Table == want.Table {
				return nil
			}
		}
	}
	return netlink.RuleAdd(want)
}

// vpnOutSweepRules deletes every rule selecting on this interface except the one for
// keepTable. Pass keepTable 0 to remove all of them, which is what teardown wants.
//
// Deleting by enumeration is the point: the rules are found in the kernel's own list,
// so each delete is issued against a rule that demonstrably exists with the fields it
// actually has, rather than against a template whose unset fields match who knows what.
func vpnOutSweepRules(iface string, keepTable int) {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return
	}
	for i := range rules {
		r := rules[i]
		if r.OifName != iface || (keepTable != 0 && r.Table == keepTable) {
			continue
		}
		if err := netlink.RuleDel(&r); err != nil {
			logger.Warning("vpn outbound: could not remove a stale ip rule for", iface, ":", err)
		}
	}
}

// vpnOutSetRPFilter writes a per-interface rp_filter. Best effort: a kernel without
// the knob, or a container that mounted /proc read-only, is not a reason to refuse to
// bring the tunnel up.
func vpnOutSetRPFilter(iface string, value int) {
	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", iface)
	if err := os.WriteFile(path, []byte(strconv.Itoa(value)), 0o644); err != nil {
		logger.Warning("vpn outbound: could not relax rp_filter on", iface, ":", err)
	}
}

// vpnOutRelaxHostRPFilter moves net.ipv4.conf.all.rp_filter from STRICT to LOOSE, and
// only in that direction.
//
// Host-wide, which is why it is this conservative. Loose still validates that a source
// address is reachable by SOME route, so it keeps the property strict mode is usually
// there for; it just stops requiring the reply to arrive on the same interface the
// route table would have chosen, which is exactly what a tunnel whose route lives in a
// private table cannot satisfy.
//
// Never written when already 0 (an operator who disabled it entirely is not overruled)
// and never lowered to 0 by us. nftables.go's ensureVpnHostNetworking already sets this
// to 2 when a VPN inbound is provisioned, so on most hosts this is a no-op; it exists
// for the box that only dials OUT and never runs that path.
func vpnOutRelaxHostRPFilter() {
	const path = "/proc/sys/net/ipv4/conf/all/rp_filter"
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if strings.TrimSpace(string(raw)) != "1" {
		return
	}
	if err := os.WriteFile(path, []byte("2"), 0o644); err != nil {
		logger.Warning("vpn outbound: could not relax net.ipv4.conf.all.rp_filter:", err)
		return
	}
	logger.Info("vpn outbound: relaxed net.ipv4.conf.all.rp_filter from strict to loose,",
		"which a tunnel whose egress route lives in a private table requires")
}

func (s *VpnOutboundService) load() []VpnOutboundConfig {
	var settingService SettingService
	raw, err := settingService.getString(vpnOutboundsSettingKey)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []VpnOutboundConfig
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		logger.Warning("vpn outbound: bad vpnOutbounds setting:", err)
		return nil
	}
	return out
}

func (s *VpnOutboundService) persist(list []VpnOutboundConfig) error {
	var settingService SettingService
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return settingService.setString(vpnOutboundsSettingKey, string(b))
}

// applyVpnOutboundsWith rewrites the outbound list so every enabled tunnel is a
// freedom outbound pinned to its interface. Derived from the stored tunnels on every
// config build rather than saved into the template, for the same reason the SSH
// facade is (applySshOutboundsWith): the interface name is decided by whatever the
// client negotiated this time round, so a copy written into the template would be
// stale the first time a peer handed back a different device.
//
// Same tag is MERGED in place, so an operator who also hand-wrote an outbound with
// this tag gets the working one rather than a duplicate tag the core would reject.
// Merged rather than replaced: the row used to be rebuilt from scratch on every
// config build, which silently threw away every sockopt the operator had set on it
// (a dialerProxy, a firewall mark, the keep-alive timers), with the panel still
// showing them because they were still in the template.
//
// Forced, and only these: `protocol`, `settings` and `sockopt.interface`. The rest of
// the row is the operator's.
func applyVpnOutboundsWith(config *xray.Config, tunnels []VpnOutboundConfig) error {
	if len(tunnels) == 0 {
		return nil
	}
	var obs []map[string]any
	if len(config.OutboundConfigs) > 0 {
		if err := json.Unmarshal(config.OutboundConfigs, &obs); err != nil {
			return err
		}
	}
	pinned := false
	for _, t := range tunnels {
		if t.Tag == "" {
			continue
		}
		ob := map[string]any{}
		at := -1
		for i, existing := range obs {
			if tag, _ := existing["tag"].(string); tag == t.Tag {
				ob, at = existing, i
				break
			}
		}
		if !t.Enable || t.Iface == "" || vpnOutIfaceGone(t.Iface) {
			// FAIL CLOSED. A tunnel with no device to bind to would otherwise be left
			// as the operator's plain freedom outbound, and that is not an error to
			// Xray: it is an unbound socket, so every byte routed to this tag leaves
			// through the host's own WAN while the operator believes it is inside a
			// VPN. Refusing the traffic is the only answer that cannot be mistaken
			// for working.
			//
			// The device is checked, not assumed, because the core will NOT catch it:
			// system_dialer.go swallows a failed BindToDevice, logging it at Info,
			// and the panel ships loglevel warning, so a pin to a device that has gone
			// away is a silent leak with no log line anywhere. Measured: an outbound
			// pinned to a nonexistent device transferred 5,000,000 of 5,000,000 bytes.
			if at < 0 {
				continue
			}
			obs[at] = map[string]any{
				"tag":      t.Tag,
				"protocol": "blackhole",
				"settings": map[string]any{},
			}
			continue
		}
		ob["tag"] = t.Tag
		ob["protocol"] = "freedom"
		// UseIP because the tunnel is being asked to carry the traffic, and a
		// name resolved on the host's own resolver before the socket is pinned
		// would answer for the host's network, not the tunnel's. Forced over
		// whatever the row said for that reason: it is not a preference.
		ob["settings"] = map[string]any{"domainStrategy": "UseIP"}
		ob["streamSettings"] = vpnOutStreamSettings(t.Tag, ob["streamSettings"], t.Iface)
		if via := vpnOutSendThrough(t.Tag, ob["sendThrough"], t.Iface); via != "" {
			ob["sendThrough"] = via
		} else {
			delete(ob, "sendThrough")
		}
		// Mux is DROPPED, never carried across. It replaces the destination with the
		// marker host v1.mux.cool:9527, which a freedom outbound has to resolve and
		// cannot, so the tag stops carrying anything at all. Measured: a muxed tunnel
		// outbound transferred 0 of 5,000,000 bytes, billed 0, and logged nothing,
		// because the dial error is Info and the panel ships loglevel warning. The old
		// build-a-fresh-map synthesis dropped it as a side effect; now it is deliberate,
		// because the merge would otherwise resurrect one saved by an older panel or
		// typed into the JSON tab.
		delete(ob, "mux")
		if at >= 0 {
			obs[at] = ob
		} else {
			obs = append(obs, ob)
		}
		pinned = true
	}
	out, err := json.Marshal(obs)
	if err != nil {
		return err
	}
	config.OutboundConfigs = out
	if pinned {
		vpnOutEnableOutboundStats(config)
	}
	return nil
}

// vpnOutStreamSettings folds the tunnel's device into whatever streamSettings the
// row already carried.
//
// SO_BINDTODEVICE is the entire mechanism, so `interface` is forced; every other
// sockopt (tcpFastOpen, tcpMptcp, mark, the keep-alive timers, addressPortStrategy,
// penetrate, trustedXForwardedFor) belongs to the operator and is left exactly as it
// was.
//
// dialerProxy is the one exception, and it is removed rather than kept. It is not a
// preference that sits alongside the pin, it CANCELS it: DialSystem returns
// redirect() at transport/internet/dialer.go:269-278, before
// effectiveSystemDialer.Dial, which is the only caller of applyOutboundSocketOptions
// and therefore the only place the interface is bound. Verified by differential test:
// an outbound pinned to a nonexistent device logs "failed to set Interface" once with
// dialerProxy absent and not at all with it present, so the bind is never even
// attempted. Keeping both would leave a tunnel outbound quietly egressing through
// somebody else's tag while every screen in the panel still called it a VPN.
//
// A streamSettings or sockopt that is absent, null, or not an object at all is
// replaced rather than merged into. There is nothing to merge with, and passing a
// hand-edited `"sockopt": "eth0"` through makes Xray refuse the WHOLE config, which
// takes every other outbound down with it.
func vpnOutStreamSettings(tag string, existing any, iface string) map[string]any {
	stream, _ := existing.(map[string]any)
	if stream == nil {
		stream = map[string]any{}
	}
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt == nil {
		sockopt = map[string]any{}
	}
	if proxy, set := sockopt["dialerProxy"]; set && proxy != "" {
		logger.Warning("vpn outbound:", tag, "has dialerProxy", proxy,
			"set, which would bypass the tunnel entirely; ignoring it and keeping the interface pin")
		delete(sockopt, "dialerProxy")
	}
	sockopt["interface"] = iface
	stream["sockopt"] = sockopt
	return stream
}

// vpnOutSendThrough decides what a tunnel outbound's `sendThrough` is allowed to be.
//
// The field pins the LOCAL SOURCE ADDRESS a connection is dialled from, and it works
// ALONGSIDE the interface pin rather than instead of it. The core binds the device in
// the dialer's Control hook and the source address in the bind() that follows
// (transport/internet/system_dialer.go), so both take effect and neither cancels the
// other. Measured on the shipped core against a device carrying two addresses:
// sendThrough moved the source off the kernel's choice onto the second address and
// carried 1,000,000 of 1,000,000 bytes.
//
// The failure is what makes this function necessary. An address that is NOT on the
// tunnel's device still binds, because it belongs to the host and the kernel only
// checks that much, and the SYN then leaves the tunnel carrying a source the far end
// cannot answer. Measured with the host's own WAN address on a pinned outbound: the
// inbound answers the client SUCCESS, the client sends, 0 of 1,000,000 bytes are
// counted, the connection is reset 81 seconds later, and at the loglevel the panel
// ships the core logs NOTHING about any of it. That is the same silent shape as mux
// and dialerProxy, which this file already drops, and an operator typing into a box
// labelled "send through" is far more likely to reach for a host address than for the
// tunnel's own.
//
// So the value is kept only when it names an address the device really has, which is
// the one case where it does something useful: a tunnel that negotiated more than one
// address, where the operator is choosing between them.
func vpnOutSendThrough(tag string, existing any, iface string) string {
	via, _ := existing.(string)
	via = strings.TrimSpace(via)
	if via == "" {
		return ""
	}
	ip := net.ParseIP(via)
	if ip == nil {
		// Not a bare address, and every other shape this field accepts is wrong on a
		// tunnel. Two are worse than wrong: a hostname makes the core refuse the WHOLE
		// config ("unable to send through", infra/conf/xray.go), which takes every
		// inbound down with it, and `origin`/`srcip` bind the address of the panel's own
		// listener or of the remote client, neither of which is ever on a tunnel
		// (measured: "connect: invalid argument", 0 bytes, nothing logged). A CIDR is
		// the same story with a step in front: the core picks a RANDOM address out of
		// the prefix, which the host does not have, so the bind fails.
		logger.Warning("vpn outbound:", tag, "has sendThrough", via,
			"which cannot be an address on", iface+";",
			"ignoring it and keeping the interface pin")
		return ""
	}
	addrs, err := vpnOutIfaceAddrs(iface)
	if err != nil {
		// Inconclusive, so the operator's value stands. It cannot leak (the interface
		// pin is untouched either way), and dropping a legitimate one on a transient
		// netlink error would silently change which address the tunnel dials from.
		return via
	}
	for _, have := range addrs {
		if have.Equal(ip) {
			return via
		}
	}
	logger.Warning("vpn outbound:", tag, "has sendThrough", via,
		"which is not an address on", iface,
		"so every connection through the tunnel would leave with a source the far end",
		"cannot answer, silently; ignoring it and keeping the interface pin")
	return ""
}

// vpnOutIfaceAddrs lists the addresses a tunnel device currently holds. A var so the
// synthesis can be tested on a host that has no wg0 to look at.
var vpnOutIfaceAddrs = func(iface string) ([]net.IP, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	// The LOCAL address of each, which on a point-to-point device is the near end and
	// not the peer: netlink keeps the peer separately, and binding the far end of a ppp
	// link is exactly the mistake this list exists to catch.
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if a.IPNet != nil {
			out = append(out, a.IPNet.IP)
		}
	}
	return out, nil
}

// vpnOutIfaceGone reports that the device a tunnel claims is DEFINITELY not on this
// host any more.
//
// It exists because the core fails open here and says nothing: a BindToDevice error
// is swallowed at transport/internet/system_dialer.go:127-131 and logged at Info,
// under the loglevel the panel ships, so an outbound pinned to a device that has been
// renamed or torn down since the tunnel was saved carries its traffic straight out of
// the host's WAN with no error anywhere. A ppp tunnel changing pppN across a reboot
// is the ordinary way to reach that state.
//
// Only a definite not-found counts. Any other netlink failure (a container with a
// restricted netns, a transient error) leaves the pin in place, because blackholing a
// working tunnel on an inconclusive answer trades a silent leak for a silent outage.
var vpnOutIfaceGone = func(iface string) bool {
	_, err := netlink.LinkByName(iface)
	if err == nil {
		return false
	}
	var missing netlink.LinkNotFoundError
	return errors.As(err, &missing)
}

// vpnOutEnableOutboundStats turns on the core's per-outbound byte counters.
//
// Forced whenever a tunnel was pinned, because the panel DISPLAYS these outbounds:
// the Traffic column reads outbound_traffics, which is filled only from Xray's
// `outbound>>>TAG>>>traffic>>>{up,down}link` stats, and the core registers no counter
// for any outbound at all while policy.system.statsOutbound{Up,Down}link is false.
// The shipped template (web/service/config.json) ships both false, so a tunnel that
// had carried gigabytes reported nothing and every VPN row read 0 B / 0 B forever.
// Leaving the operator to find the two switches that make the panel's own column work
// is not an answer for a row the panel synthesized and they cannot see.
//
// Best effort by design. An unparseable policy block must not cost the tunnels their
// pinning, which is what failing the caller would do: GetXrayConfig logs and leaves
// the outbound list alone, and an unpinned freedom outbound egresses through the
// host's WAN.
func vpnOutEnableOutboundStats(config *xray.Config) {
	var policy map[string]any
	if len(config.Policy) > 0 {
		if err := json.Unmarshal(config.Policy, &policy); err != nil {
			logger.Warning("vpn outbound: leaving the traffic counters alone,",
				"the policy block does not parse:", err)
			return
		}
	}
	if policy == nil {
		policy = map[string]any{}
	}
	system, _ := policy["system"].(map[string]any)
	if system == nil {
		system = map[string]any{}
	}
	system["statsOutboundUplink"] = true
	system["statsOutboundDownlink"] = true
	policy["system"] = system
	out, err := json.Marshal(policy)
	if err != nil {
		logger.Warning("vpn outbound: could not enable the outbound traffic counters:", err)
		return
	}
	config.Policy = out
}

// findVpnTunnel returns the stored tunnel with this tag, if there is one.
func findVpnTunnel(list []VpnOutboundConfig, tag string) (VpnOutboundConfig, bool) {
	for _, c := range list {
		if c.Tag == tag {
			return c, true
		}
	}
	return VpnOutboundConfig{}, false
}
