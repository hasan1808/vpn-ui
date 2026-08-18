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

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/goccy/go-json"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
//
// The tun inbound does appear elsewhere in this feature, pointing the other way and
// with that facility deliberately left off: vpnoutcarrier.go uses one as a CARRIER, a
// device whose traffic leaves through a chosen outbound, which is the opposite
// direction and asks nothing global of the core.

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

	// Via is the tag of ANOTHER vpn tunnel that carries this one: this tunnel's own
	// outer transport travels through that tunnel's netdev, so the server it dials sees
	// the carrier's exit address and never this host's. Empty is the ordinary case, a
	// tunnel dialled straight out of the host's WAN. See vpnoutvia.go for the mechanism.
	//
	// POPULATED FROM THE OUTBOUND ROW'S sockopt.dialerProxy. There is one chaining
	// control in the panel and it is the Dialer Proxy select, on every outbound including
	// a tunnel; the browser posts whatever it holds into this field. The stored name
	// stays Via because that is what the routing side calls it, and because the key does
	// not survive into the Xray config at all (vpnOutStreamSettings), where dialerProxy
	// means "dial through that outbound instead" and would cancel the interface pin.
	//
	// omitempty is load-bearing rather than tidy. Every stored tunnel predates this
	// field, and the whole list is re-marshalled and written back whenever anything in
	// it changes; without omitempty that write would add `"via":""` to rows nobody
	// touched, and the list is also what applyVpnOutboundsWith derives the Xray
	// outbounds from, so an upgrade would rewrite and restart things it had no reason
	// to.
	Via string `json:"via,omitempty" form:"via"`

	// CarriedOverProxy is true while this tunnel is being raised through a carrier that
	// is an XRAY OUTBOUND rather than a netdev of its own (vpnoutcarrier.go). It is set
	// by the framework immediately before Up and read by the two drivers that have to
	// put something different on the wire for it: charon's kernel ESP is proto 50, and
	// a proxy carrier moves only TCP and UDP, so IKEv2 and L2TP/IPsec force NAT-T
	// encapsulation when this is set and leave it alone when it is not.
	//
	// json:"-" because it is a fact about the CARRIER, derived on every raise from the
	// tunnel's Via and the outbound list. Persisting it would create a second copy of
	// something already stored, free to disagree with it after an operator edits the
	// outbound the tunnel rides on.
	CarriedOverProxy bool `json:"-"`

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
	// Carriers first. A tunnel carried by another is steered into that other tunnel's
	// ROUTE TABLE, so raising it while its carrier is still down would find an empty
	// table; the blackhole vpnOutBindEgress parks there is what makes that a dropped
	// packet rather than a leak, but a tunnel that comes up and immediately black-holes
	// itself is not what the operator asked for either. A cycle cannot be saved through
	// the panel, so one here was hand-edited into the setting: its members are skipped
	// rather than raised in whatever order the list happens to hold.
	order, dropped := vpnOutViaOrder(all)
	for _, tag := range dropped {
		logger.Warning("vpn outbound: not raising", tag,
			"because it is part of a loop of tunnels carrying each other")
	}
	for _, i := range order {
		cfg := all[i]
		if !cfg.Enable {
			continue
		}
		iface, err := s.bringUp(cfg, all)
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
	// Reconciled once at the end, over the whole list. Each raise installed its own
	// pair of rules already; this is the repair pass, and it is the only thing that
	// removes a steer rule left behind by a crash or pointing at a table number that a
	// rebuilt device has since given up.
	vpnOutApplyVia(all, vpnOutApplyCarriers(all, (&SshOutboundService{}).List()))
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

	cfg.Via = strings.TrimSpace(cfg.Via)
	// Refused BEFORE the driver validates and long before anything is raised. Every one
	// of these is a configuration that cannot be expressed as routing rules, and the
	// three of them fail in ways nobody would connect back to this field: a loop makes
	// both tunnels dead, a Via naming an Xray outbound has no netdev to steer into, and
	// a Via naming itself installs a rule sending a tunnel's handshake into its own
	// table.
	sshList := (&SshOutboundService{}).List()
	carriers, _ := vpnOutCarrierPlan(all, sshList, vpnOutTemplateOutbounds())
	if err := vpnOutViaCheck(all, vpnOutCarrierExtras(carriers), cfg); err != nil {
		return cfg, err
	}
	// The per-kind gate, refused here as well as at the raise so an operator learns it
	// from the form rather than from a tunnel that comes up and moves nothing.
	if cfg.Via != "" {
		for _, c := range carriers {
			if c.Tag == cfg.Via {
				if why := vpnOutCarrierRefusal(cfg, c); why != "" {
					return cfg, errors.New(why)
				}
				break
			}
		}
	}
	// Turning a CARRIER off is the fourth refusal, and it is the one that is not about
	// this tunnel at all: the tunnels riding on it would keep running with their steer
	// rules swept, dialling their servers straight out of the host's WAN.
	if !cfg.Enable {
		if err := vpnOutViaInUse(all, cfg.Tag); err != nil {
			return cfg, err
		}
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
		// The list AS IT WILL BE, so a carried tunnel finds the carrier's live device.
		// Copied rather than appended in place: `out` is appended to again below, and
		// two appends sharing one backing array is not a thing to leave to the reader.
		pending := make([]VpnOutboundConfig, len(out), len(out)+1)
		copy(pending, out)
		iface, err := s.bringUp(cfg, append(pending, cfg))
		if err != nil {
			return cfg, err
		}
		cfg.Iface = iface
	} else {
		// Saved disabled: take it down and forget the interface, so the synthesized
		// outbound is dropped rather than left bound to a device that is gone. The
		// carried tunnels' steer rules go first: vpnOutUnbindEgress destroys this
		// tunnel's table, and a steer rule that outlives the table it points at is the
		// measured leak - the lookup falls through to main and the carried tunnel
		// egresses in the clear.
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
	// Over the whole list, because this save can have changed somebody else's answer:
	// disabling a tunnel that carries two others has to remove their steer rules, and
	// they are not in this call anywhere.
	vpnOutApplyVia(out, vpnOutApplyCarriers(out, (&SshOutboundService{}).List()))
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
	// Refused while anything is riding on it: the teardown below sweeps their steer
	// rules with the table, and they would go on running with their outer transport
	// leaving in the clear.
	if err := vpnOutViaInUse(all, tag); err != nil {
		return err
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
	// After the teardown, over what is left. Deleting a CARRIER strands every steer
	// rule pointing into its table, and vpnOutUnbindEgress has just taken the table's
	// blackhole with it: without this pass the tunnels it carried would fall through to
	// main and leave in the clear.
	vpnOutApplyVia(out, vpnOutApplyCarriers(out, (&SshOutboundService{}).List()))
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
//
// Carried tunnels first, which is the reverse of the boot order. A carrier torn down
// while something it carries is still running leaves that tunnel steered into a table
// whose device has gone, and the fall-through is main: the tunnel keeps running and
// keeps talking to its server, in the clear, for as long as the panel takes to reach it
// in the list.
func (s *VpnOutboundService) StopAll() {
	all := s.load()
	order, dropped := vpnOutViaOrder(all)
	// A hand-edited loop is not a reason to leave a netdev up: its members are stopped
	// after everything else, in whatever order they are stored.
	for _, tag := range dropped {
		for i, c := range all {
			if c.Tag == tag {
				order = append(order, i)
			}
		}
	}
	for n := len(order) - 1; n >= 0; n-- {
		c := all[order[n]]
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
// `all` is the tunnel list this raise belongs to, which is how a carried tunnel finds
// the device its carrier came up on.
func (s *VpnOutboundService) bringUp(cfg VpnOutboundConfig, all []VpnOutboundConfig) (string, error) {
	drv, err := vpnOutDriverFor(cfg.Kind)
	if err != nil {
		return "", err
	}
	// BEFORE the client is started, not after. The steer rule needs this tunnel's
	// SERVER address and its carrier's TABLE, and neither of those waits on a device
	// that does not exist yet - while a WireGuard client sends its first handshake the
	// instant its peer is configured, so a rule added afterwards arrives after the
	// packet it was meant to carry has already left in the clear.
	//
	// Refusing here is also what makes a down carrier fail CLOSED. Raising the tunnel
	// anyway would give the operator a tunnel that works, reports itself up, and dials
	// its server straight out of the host's WAN - the exact thing they configured this
	// field to prevent.
	var carrier vpnOutCarrier
	if cfg.Via != "" {
		var facts vpnOutViaFacts
		carrier, facts, err = vpnOutResolveCarrier(cfg.Via, all, (&SshOutboundService{}).List())
		if err != nil {
			return "", err
		}
		// The per-kind gate, and it only ever fires for a carrier that is an Xray
		// outbound. Steering into a netdev is L4-agnostic, so a tunnel carrier takes
		// GRE and ESP whole; a proxy carrier moves TCP and UDP and drops the rest,
		// which for PPTP means the control channel would ride and the data channel
		// would not. Half a tunnel is worse than a refusal: it authenticates, reports
		// itself up, and moves nothing.
		if why := vpnOutCarrierRefusal(cfg, carrier); why != "" {
			return "", errors.New(why)
		}
		// Read by the IPsec drivers, which have to force NAT-T encapsulation to put
		// their ESP inside UDP where a proxy carrier can see it. Set before Up because
		// it changes the config the client is started with.
		cfg.CarriedOverProxy = carrier.Bridged()
		if err := vpnOutSteerVia(cfg, facts); err != nil {
			return "", err
		}
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
	// Both devices exist now, so the double-encapsulation arithmetic can finally be
	// done. A warning and not a refusal: an MTU that is too big by a few bytes gives a
	// tunnel that pings and stalls on real traffic, which is worth saying out loud, but
	// the exact overhead depends on the cipher that was negotiated and this panel is
	// guessing at it.
	if cfg.Via != "" && carrier.Iface != "" {
		vpnOutViaMtuCheck(cfg, iface, carrier.Iface)
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
	//
	// The steer rules pointing INTO this table are deliberately left alone here (table
	// 0 below turns that half off): they belong to the tunnels this one carries, they
	// are live, and vpnOutApplyVia runs right after every raise and owns them. Deleting
	// one here to add it back a moment later would open exactly the window this whole
	// scheme exists to close.
	vpnOutSweepRules(iface, 0, table)

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

	// The blackhole first and the device route second: see vpnOutEgressRoutes for why
	// that order is the fail-closed one.
	for _, r := range vpnOutEgressRoutes(table, link.Attrs().Index) {
		if err := vpnOutReplaceRoute(r); err != nil {
			return fmt.Errorf("cannot install the egress routes for %s: %w", iface, err)
		}
	}
	return nil
}

// vpnOutEgressRoutes is everything one tunnel's private table holds, in the order it
// has to be installed. Pure, so what goes into a table is a decision that can be
// checked without a kernel.
//
// TWO routes, and the second one is what makes carrying a tunnel inside another safe.
//
// The oif scheme is intrinsically fail-closed because its rule names the DEVICE: no
// device, no match, no packet. A steer rule (vpnoutvia.go) names this TABLE instead,
// and a table does not disappear with its device - the device route goes, the lookup
// finds nothing, and the kernel falls through to main. Measured: with the carrier's
// device deleted, 100% of the carried tunnel left in the clear out of the host's WAN
// with nothing logged anywhere.
//
// A blackhole default at metric 1000 fixes it and is measurably inert while the tunnel
// is up: the device route is metric 0 and wins every lookup. When the device goes, the
// blackhole is what is left, and the carried device shows a rising TX errors count -
// a visible symptom rather than a silent one.
//
// Returned for EVERY tunnel, not only the ones carrying something. It costs one route,
// it makes the table self-consistent for the plain oif path too (a pinned socket whose
// device vanished mid-connection gets ENETUNREACH instead of the host's WAN), and a
// tunnel that becomes a carrier later is then already safe.
//
// BLACKHOLE FIRST is the order, not an accident of writing. If the second install fails
// the caller gives up and takes the tunnel down, and the table is left holding whatever
// the first one put there: a lone blackhole drops traffic, a lone device route works
// until the device goes and then leaks.
func vpnOutEgressRoutes(table, linkIndex int) []*netlink.Route {
	// 0.0.0.0/0 is written OUT rather than left as a nil Dst meaning "everything".
	// netlink refuses a route with no destination, no source and no gateway outright
	// ("either Dst.IP, Src.IP or Gw must be set", route_linux.go), before it builds
	// the message, so a nil Dst here never reached the kernel: it failed every raise
	// of every protocol, and bringUp took the tunnel back down and reported the
	// tunnel itself as unusable.
	anywhere := func() *net.IPNet {
		return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	return []*netlink.Route{
		{
			Table:    table,
			Dst:      anywhere(),
			Type:     unix.RTN_BLACKHOLE,
			Priority: vpnOutBlackholeMetric,
		},
		// A plain `default dev X` with no nexthop, which is what a point-to-point device
		// wants. Every tunnel this framework raises is p2p or tun; a device that needed a
		// gateway would need this widened rather than worked around in its driver.
		{
			LinkIndex: linkIndex,
			Table:     table,
			Dst:       anywhere(),
			Scope:     netlink.SCOPE_LINK,
		},
	}
}

// vpnOutReplaceRoute and vpnOutFlushTable are the two places this file writes routes.
// Vars so the teardown ORDER, which is where the leak lives, can be observed in a test
// without a kernel.
var vpnOutReplaceRoute = func(r *netlink.Route) error { return netlink.RouteReplace(r) }

var vpnOutFlushTable = func(table int) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return
	}
	for i := range routes {
		_ = netlink.RouteDel(&routes[i])
	}
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
	//
	// ORDER. The rules go first and the routes second, and within the rules the steers
	// pointing into this table go before the blackhole that backstops them. Reversed,
	// there is a window in which the table has been emptied and a carried tunnel is
	// still being steered into it: the lookup falls through to main and every byte
	// leaves in the clear. That window is the measured failure, and the whole reason
	// this function computes the table BEFORE sweeping rather than after.
	table := vpnOutTableOf(iface)
	vpnOutSweepRules(iface, table, 0)
	if table != 0 {
		vpnOutFlushTable(table)
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

// vpnOutSweepRules deletes the rules belonging to one tunnel: every rule selecting on
// this interface except the one for keepTable (pass keepTable 0 to remove all of them,
// which is what teardown wants), AND every via rule steering into `table`.
//
// The second half is new and it is the teardown ordering fix. A steer rule points at a
// TABLE, and this function's caller is about to delete that table's routes - including
// the blackhole that is the only thing standing between a carried tunnel and the main
// table. Sweeping the steers first is what keeps a teardown from turning into the
// measured leak. Pass table 0 to skip it, which is what a rebind wants: those steers are
// live, and the reconcile that follows a raise owns them.
//
// Deleting by enumeration is the point: the rules are found in the kernel's own list,
// so each delete is issued against a rule that demonstrably exists with the fields it
// actually has, rather than against a template whose unset fields match who knows what.
// The DECISION of which ones are stale is vpnOutStaleRuleIdx, kept pure so it can be
// tested without a kernel.
func vpnOutSweepRules(iface string, table, keepTable int) {
	have, rules, err := vpnOutListRules()
	if err != nil {
		return
	}
	for _, i := range vpnOutStaleRuleIdx(have, iface, table, keepTable) {
		if err := vpnOutDelRule(rules[i]); err != nil {
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
		ob["streamSettings"] = vpnOutStreamSettings(t.Tag, t.Via, ob["streamSettings"], t.Iface)
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
// dialerProxy is the one exception: it is CONSUMED, not discarded. On a tunnel row that
// field is the operator's carrier choice - Save copies it into Via and vpnoutvia.go turns
// it into the ip rules that send this tunnel's own outer transport through the named
// tunnel's device. What must not survive is the KEY in the emitted config, because to
// Xray it means the opposite thing: it does not sit alongside the pin, it CANCELS it.
// DialSystem returns redirect() at transport/internet/dialer.go:269-278, before
// effectiveSystemDialer.Dial, which is the only caller of applyOutboundSocketOptions
// and therefore the only place the interface is bound. Verified by differential test:
// an outbound pinned to a nonexistent device logs "failed to set Interface" once with
// dialerProxy absent and not at all with it present, so the bind is never even
// attempted. Emitted, it would send the tunnel's traffic out of the carrier's tag with
// the tunnel skipped entirely, while every screen in the panel still called it a VPN.
//
// So this deletion is deliberate and permanent, not a leftover: the panel reads the
// value, the core never sees it. `via` is passed in only to say which of those two
// happened in the log, since a row whose dialerProxy does not match the stored carrier
// is an edit that never reached the tunnel save.
//
// A streamSettings or sockopt that is absent, null, or not an object at all is
// replaced rather than merged into. There is nothing to merge with, and passing a
// hand-edited `"sockopt": "eth0"` through makes Xray refuse the WHOLE config, which
// takes every other outbound down with it.
func vpnOutStreamSettings(tag, via string, existing any, iface string) map[string]any {
	stream, _ := existing.(map[string]any)
	if stream == nil {
		stream = map[string]any{}
	}
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt == nil {
		sockopt = map[string]any{}
	}
	if proxy, set := sockopt["dialerProxy"]; set && proxy != "" {
		if name, _ := proxy.(string); name != "" && name == strings.TrimSpace(via) {
			logger.Info("vpn outbound:", tag, "is carried by", name+
				", which is routing rules and not a dialer proxy, so the key is dropped here and the interface pin stands")
		} else {
			carrier := strings.TrimSpace(via)
			if carrier == "" {
				carrier = "nothing"
			}
			logger.Warning("vpn outbound:", tag, "names", proxy,
				"as its dialer proxy but the stored tunnel is carried by", carrier+
					"; the carry follows the stored value, so re-save the tunnel to change it")
		}
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
