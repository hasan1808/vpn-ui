package service

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Clients on the Xray-native `wireguard` inbound.
//
// Xray's wireguard inbound is a device, not a user list: its settings carry
// `peers[]`, each authorised by a public key and a set of allowedIPs, and a peer has
// no email, no id, and nothing the core reports statistics against. The panel's whole
// client model is the opposite shape, so the two never met: an operator could create
// the inbound and then had no way to put an account on it, because
// AssignableInboundsFor only offers inbounds whose settings hold a `clients` array
// and this protocol's never did.
//
// The bridge is the same one the panel already uses for every protocol whose stored
// shape is not the core's: the DB keeps `clients[]`, in the panel's own shape, and the
// generated config is REWRITTEN on the way to Xray (see applyWireguardClients, called
// from GetXrayConfig). Nothing else in the panel has to learn a second shape, and the
// inbound's own `peers[]` is left alone so a peer added by hand keeps working.
//
// WHAT THIS CANNOT DO, and it is a property of the core rather than a gap here:
// wireguard.PeerConfig (third_party/Xray-core/infra/conf/wireguard.go) has no user
// field, so Xray emits no "user>>><email>>>>traffic" counter for a wireguard peer.
// A client on this protocol therefore accrues NO usage: its quota can never trip and
// it is never reported online. Expiry, the enable switch and deletion all work, since
// those are enforced by leaving the peer out of the generated config.

const (
	// wgxrayDefaultNetwork is the pool peers are addressed from when the inbound does
	// not name one. Deliberately not 10.0.0.0/24, which is what the inbound form's
	// hand-added peers have always defaulted to: a fresh panel would otherwise hand a
	// managed client the same address an operator had already pinned by hand.
	wgxrayDefaultNetwork = "10.10.0.0/24"
	// wgxrayServerHost is the first usable address of the pool, held by the inbound
	// itself, and so never handed to a peer.
	wgxrayServerHost = 1
)

// wgxrayNetwork reads the pool this inbound addresses its clients from.
func wgxrayNetwork(raw map[string]json.RawMessage) *net.IPNet {
	return wgxrayParseNetwork(jsonString(raw["clientNetwork"]))
}

// wgxrayParseNetwork resolves a configured pool, falling back to the default for
// anything absent, unparseable or not v4. Never returns nil: every caller uses the
// result to derive an address, and a nil here would be a panic on a typo.
func wgxrayParseNetwork(cidr string) *net.IPNet {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		cidr = wgxrayDefaultNetwork
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil || network == nil || network.IP.To4() == nil {
		_, network, _ = net.ParseCIDR(wgxrayDefaultNetwork)
	}
	return network
}

// wgxrayHostAt returns the nth host of a v4 network as a /32 string.
func wgxrayHostAt(network *net.IPNet, n int) string {
	base := network.IP.To4()
	if base == nil || n < 0 {
		return ""
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return ""
	}
	// The last address of the block is the broadcast one and is not a host. n is
	// compared against the count of usable hosts, so a pool that has run out returns
	// empty and the caller reports it rather than wrapping onto somebody else.
	if hosts := (1 << (32 - ones)); ones < 31 && n >= hosts-1 {
		return ""
	}
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	v += uint32(n)
	return fmt.Sprintf("%d.%d.%d.%d/32", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// WgxrayServerAddress is the inbound's own address inside the tunnel, which is what
// the core's `address` field takes and what a client's .conf routes towards.
func WgxrayServerAddress(inbound *model.Inbound) string {
	raw := map[string]json.RawMessage{}
	_ = json.Unmarshal([]byte(inbound.Settings), &raw)
	return wgxrayServerAddressFrom(raw)
}

// wgxrayServerAddressFrom is the same answer from an already-parsed raw settings map.
func wgxrayServerAddressFrom(raw map[string]json.RawMessage) string {
	network := wgxrayNetwork(raw)
	return strings.TrimSuffix(wgxrayHostAt(network, wgxrayServerHost), "/32")
}

// wgxrayServerAddressFromSettings is the same answer again for the generic
// map[string]any the config generator works in. Kept separate rather than converting
// between the two shapes: the generator runs for every inbound on every config
// build, and a re-marshal there would be paid on all of them.
func wgxrayServerAddressFromSettings(settings map[string]any) string {
	cidr, _ := settings["clientNetwork"].(string)
	network := wgxrayParseNetwork(cidr)
	return strings.TrimSuffix(wgxrayHostAt(network, wgxrayServerHost), "/32")
}

// wgxrayEffectiveDevices is how many keypairs one account gets on this inbound.
//
// The inbound's User Limit, read exactly as wg-c reads it (0 meaning the maximum
// rather than none), because the question is the same one: a customer with a phone
// and a laptop needs two keypairs, since two WireGuard devices cannot share one.
//
// It is a provisioning number here and NOT an enforced cap, which is the honest
// description: enforcing a device limit means noticing a third device, and this
// protocol reports nothing to notice it with.
func wgxrayEffectiveDevices(raw map[string]json.RawMessage) int {
	return wgcEffectiveK(userLimitPtrFromRaw(raw))
}

// ReconcileWireguardXrayKeys mints the key material and tunnel addresses every client
// of an Xray wireguard inbound needs, in place, and reports whether anything changed.
//
// Modelled on WgcService.ReconcileKeys and deliberately the same shape: the server
// keypair first, then one keypair per device slot per client, grown to the User Limit
// and trimmed past it. It works on raw JSON maps for the reason stated all over this
// package, that normalising through model.Client drops any key that struct does not
// model.
//
// Addresses are assigned from the lowest free host of the pool and then never move.
// An address is what authorises a peer AND what the customer's installed .conf claims,
// so re-deriving one from a list position would break every config handed out after
// any account is deleted.
func ReconcileWireguardXrayKeys(inbound *model.Inbound) (bool, error) {
	if inbound == nil || inbound.Protocol != model.WireGuard {
		return false, nil
	}
	var raw map[string]json.RawMessage
	if len(inbound.Settings) > 0 {
		if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil {
			return false, err
		}
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	changed := false

	// The device keypair. `secretKey` is the core's own field name, and `pubKey` is
	// what the inbound form already stores beside it, so both keep their spelling.
	if strings.TrimSpace(jsonString(raw["secretKey"])) == "" {
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return changed, err
		}
		setRawString(raw, "secretKey", priv.String())
		setRawString(raw, "pubKey", priv.PublicKey().String())
		changed = true
	} else if priv, err := wgtypes.ParseKey(jsonString(raw["secretKey"])); err == nil {
		if jsonString(raw["pubKey"]) != priv.PublicKey().String() {
			setRawString(raw, "pubKey", priv.PublicKey().String())
			changed = true
		}
	}

	var clients []map[string]json.RawMessage
	if cb, ok := raw["clients"]; ok {
		_ = json.Unmarshal(cb, &clients)
	}
	if clients == nil {
		// The key itself has to exist even when empty, or AssignableInboundsFor and
		// the projection both read this inbound as one that cannot hold clients.
		raw["clients"] = json.RawMessage("[]")
		changed = true
	}

	network := wgxrayNetwork(raw)
	devices := wgxrayEffectiveDevices(raw)

	// Every address already spoken for, so a new one never lands on a peer that
	// exists. The hand-authored peers[] count too: those are the operator's, the
	// panel did not hand them out, and colliding with one would break a working
	// tunnel that has nothing to do with the accounts layer.
	taken := map[string]bool{}
	taken[wgxrayHostAt(network, wgxrayServerHost)] = true
	for _, c := range clients {
		var addrs []string
		if ab, ok := c["addresses"]; ok {
			_ = json.Unmarshal(ab, &addrs)
		}
		for _, a := range addrs {
			taken[strings.TrimSpace(a)] = true
		}
	}
	var manual []map[string]json.RawMessage
	if pb, ok := raw["peers"]; ok {
		_ = json.Unmarshal(pb, &manual)
	}
	for _, peer := range manual {
		var addrs []string
		if ab, ok := peer["allowedIPs"]; ok {
			_ = json.Unmarshal(ab, &addrs)
		}
		for _, a := range addrs {
			taken[strings.TrimSpace(a)] = true
		}
	}

	nextFree := func() string {
		for n := wgxrayServerHost + 1; ; n++ {
			addr := wgxrayHostAt(network, n)
			if addr == "" {
				return ""
			}
			if !taken[addr] {
				taken[addr] = true
				return addr
			}
		}
	}

	exhausted := false
	for _, c := range clients {
		var slots []map[string]json.RawMessage
		if db, ok := c["devices"]; ok {
			_ = json.Unmarshal(db, &slots)
		}
		var addrs []string
		if ab, ok := c["addresses"]; ok {
			_ = json.Unmarshal(ab, &addrs)
		}

		// Grow to the User Limit, then trim past it, so lowering the limit revokes
		// the surplus keys instead of leaving them able to connect for ever.
		for len(slots) < devices {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return changed, err
			}
			d := map[string]json.RawMessage{}
			setRawString(d, "privKey", key.String())
			setRawString(d, "pubKey", key.PublicKey().String())
			setRawString(d, "psk", "")
			slots = append(slots, d)
			changed = true
		}
		if len(slots) > devices {
			slots = slots[:devices]
			changed = true
		}
		for len(addrs) < len(slots) {
			addr := nextFree()
			if addr == "" {
				exhausted = true
				break
			}
			addrs = append(addrs, addr)
			changed = true
		}
		if len(addrs) > len(slots) {
			addrs = addrs[:len(slots)]
			changed = true
		}

		// A stored private key is the truth; the public one is only ever derived from
		// it, so a hand-edited settings blob cannot leave a peer authorised by a key
		// nobody holds.
		for _, d := range slots {
			if key, err := wgtypes.ParseKey(jsonString(d["privKey"])); err == nil {
				if jsonString(d["pubKey"]) != key.PublicKey().String() {
					setRawString(d, "pubKey", key.PublicKey().String())
					changed = true
				}
			}
		}

		db, _ := json.Marshal(slots)
		c["devices"] = db
		ab, _ := json.Marshal(addrs)
		c["addresses"] = ab
		// The legacy trio mirrors slot 0, matching wg-c, so anything reading the flat
		// fields (an export, an older template) sees the account's first device.
		if len(slots) > 0 {
			setRawString(c, "privKey", jsonString(slots[0]["privKey"]))
			setRawString(c, "pubKey", jsonString(slots[0]["pubKey"]))
			setRawString(c, "psk", jsonString(slots[0]["psk"]))
		}
	}
	if exhausted {
		logger.Warningf("wireguard inbound %d: the client pool %s has no free addresses left; "+
			"widen clientNetwork to admit more accounts", inbound.Id, network.String())
	}

	if changed {
		cb, _ := json.Marshal(clients)
		if clients != nil {
			raw["clients"] = cb
		}
		out, err := json.Marshal(raw)
		if err != nil {
			return changed, err
		}
		inbound.Settings = string(out)
	}
	return changed, nil
}

// ReconcileAllWireguardXrayKeys reconciles and persists every Xray wireguard inbound,
// reporting whether any of them changed (the caller then regenerates the core config).
//
// Called from the same place the wg-c reconcile is, so an account added to one of
// these inbounds has its keys and address before the config is next generated.
func ReconcileAllWireguardXrayKeys() bool {
	db := database.GetDB()
	if db == nil {
		return false
	}
	var inbounds []*model.Inbound
	if err := db.Model(model.Inbound{}).Where("protocol = ?", model.WireGuard).Find(&inbounds).Error; err != nil {
		logger.Warning("wireguard: cannot list inbounds to reconcile keys: ", err)
		return false
	}
	any := false
	for _, inbound := range inbounds {
		changed, err := ReconcileWireguardXrayKeys(inbound)
		if err != nil {
			logger.Warningf("wireguard inbound %d: cannot reconcile keys: %v", inbound.Id, err)
			continue
		}
		if !changed {
			continue
		}
		if err := db.Model(model.Inbound{}).Where("id = ?", inbound.Id).
			Update("settings", inbound.Settings).Error; err != nil {
			logger.Warningf("wireguard inbound %d: cannot save reconciled keys: %v", inbound.Id, err)
			continue
		}
		any = true
	}
	return any
}

// applyWireguardClients rewrites one wireguard inbound's settings into the shape the
// core takes: every enabled client's device keys become peers, and `clients` goes.
//
// enabledFor answers "may this account be served", which is the account-wide depletion
// and expiry state ANDed with the entry's own enable flag, exactly as the generic
// client filter in GetXrayConfig does it. Filtering here is the whole of enforcement
// for this protocol: a peer left out of the config cannot complete a handshake.
//
// The inbound's own `peers` are kept and the managed ones appended, so a peer an
// operator pinned by hand is never quietly dropped by an account edit.
func applyWireguardClients(settings map[string]any, enabledFor func(email string, entryEnabled bool) bool) {
	clients, ok := settings["clients"].([]any)
	// Always removed, present or not: `clients` means nothing to the core, and leaving
	// it in the generated config invites the next reader to believe it does.
	delete(settings, "clients")
	if !ok {
		return
	}

	// The device's own address inside the tunnel, which has to be in the pool the
	// peers are addressed from.
	//
	// Xray's default when the field is absent is the bogon 10.0.0.1
	// (third_party/Xray-core/infra/conf/wireguard.go), so an inbound handing its
	// clients 10.10.0.x had its device sitting in a different subnet from every one
	// of them. Derived from clientNetwork rather than pinned, so an operator who
	// widens or moves the pool moves the device with it.
	//
	// Never overwritten: an imported inbound, or one an operator configured by hand,
	// may already name an address, and that one is the truth about what its existing
	// peers are talking to.
	if _, named := settings["address"]; !named {
		if addr := wgxrayServerAddressFromSettings(settings); addr != "" {
			settings["address"] = []any{addr}
		}
	}

	peers, _ := settings["peers"].([]any)
	out := make([]any, 0, len(peers)+len(clients))
	out = append(out, peers...)

	for _, item := range clients {
		c, ok := item.(map[string]any)
		if !ok {
			continue
		}
		email, _ := c["email"].(string)
		entryEnabled := true
		if v, ok := c["enable"].(bool); ok {
			entryEnabled = v
		}
		if !enabledFor(email, entryEnabled) {
			logger.Infof("wireguard: leaving %s out of the peer list (disabled, expired or out of traffic)", email)
			continue
		}

		var addrs []string
		if raw, ok := c["addresses"].([]any); ok {
			for _, a := range raw {
				if s, ok := a.(string); ok && strings.TrimSpace(s) != "" {
					addrs = append(addrs, strings.TrimSpace(s))
				}
			}
		}
		devices, _ := c["devices"].([]any)
		for i, item := range devices {
			d, ok := item.(map[string]any)
			if !ok {
				continue
			}
			pub, _ := d["pubKey"].(string)
			if strings.TrimSpace(pub) == "" {
				continue
			}
			if i >= len(addrs) {
				// No address means no allowedIPs, and Xray's default for a peer with
				// none is 0.0.0.0/0: that one peer would be authorised to source ANY
				// address, including every other client's. Skipped rather than
				// emitted; the reconcile assigns one on the next pass.
				logger.Warningf("wireguard: %s device %d has no tunnel address and is not being served", email, i)
				continue
			}
			peer := map[string]any{
				"publicKey":  strings.TrimSpace(pub),
				"allowedIPs": []any{addrs[i]},
			}
			if psk, _ := d["psk"].(string); strings.TrimSpace(psk) != "" {
				peer["preSharedKey"] = strings.TrimSpace(psk)
			}
			out = append(out, any(peer))
		}
	}
	settings["peers"] = out
}

// WgxrayClientConfig is one device's WireGuard configuration.
//
// The field NAMES are WgcClientConfig's, not new ones, because the panel renders both
// through the same modal (modals/wgcConfigModal): one config viewer for the two
// WireGuard implementations rather than a second copy of it to keep in step. Remark
// is always empty here, since this protocol has no external-proxy endpoints.
type WgxrayClientConfig struct {
	DeviceIndex int    `json:"deviceIndex"`
	IP          string `json:"ip"`        // this device's tunnel address, the .conf's Address
	Remark      string `json:"remark"`    // always empty; present for the shared viewer
	PublicKey   string `json:"publicKey"` // this device's own public key, its identifier
	Config      string `json:"config"`    // the full .conf text
	Host        string `json:"host"`
	Port        int    `json:"port"`
}

// RenderWireguardXrayConfigs returns the .conf(s) one account installs, one per device
// slot. endpointHost is the address the customer dials.
//
// AllowedIPs is IPv4-only full tunnel, matching every other protocol in this panel:
// adding ::/0 to a tunnel whose inside has no IPv6 sends the client's v6 traffic into
// a black hole, and adding neither leaks it past the tunnel entirely.
func RenderWireguardXrayConfigs(inbound *model.Inbound, email, endpointHost string) ([]WgxrayClientConfig, error) {
	if inbound == nil || inbound.Protocol != model.WireGuard {
		return nil, common.NewError("not an Xray wireguard inbound")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(inbound.Settings), &raw); err != nil {
		return nil, err
	}
	serverPub := strings.TrimSpace(jsonString(raw["pubKey"]))
	if serverPub == "" {
		if priv, err := wgtypes.ParseKey(jsonString(raw["secretKey"])); err == nil {
			serverPub = priv.PublicKey().String()
		}
	}
	// Xray's own default when the field is absent or zero, so a config generated here
	// and one the core builds for itself agree on the MTU.
	mtu := 1420
	var mtuNum float64
	if err := json.Unmarshal(raw["mtu"], &mtuNum); err == nil && mtuNum > 0 {
		mtu = int(mtuNum)
	}

	var clients []map[string]json.RawMessage
	if cb, ok := raw["clients"]; ok {
		_ = json.Unmarshal(cb, &clients)
	}
	var target map[string]json.RawMessage
	for _, c := range clients {
		if accountKey(jsonString(c["email"])) == accountKey(email) {
			target = c
			break
		}
	}
	if target == nil {
		return nil, common.NewErrorf("%s is not a client of inbound %d", email, inbound.Id)
	}

	var slots []map[string]json.RawMessage
	if db, ok := target["devices"]; ok {
		_ = json.Unmarshal(db, &slots)
	}
	var addrs []string
	if ab, ok := target["addresses"]; ok {
		_ = json.Unmarshal(ab, &addrs)
	}

	out := make([]WgxrayClientConfig, 0, len(slots))
	for i, d := range slots {
		if i >= len(addrs) {
			break
		}
		priv := strings.TrimSpace(jsonString(d["privKey"]))
		if priv == "" {
			continue
		}
		var b strings.Builder
		b.WriteString("[Interface]\n")
		fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
		fmt.Fprintf(&b, "Address = %s\n", addrs[i])
		fmt.Fprintf(&b, "MTU = %d\n", mtu)
		b.WriteString("DNS = 1.1.1.1, 1.0.0.1\n\n")
		b.WriteString("[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", serverPub)
		if psk := strings.TrimSpace(jsonString(d["psk"])); psk != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
		}
		b.WriteString("AllowedIPs = 0.0.0.0/0\n")
		fmt.Fprintf(&b, "Endpoint = %s:%d\n", endpointHost, inbound.Port)
		b.WriteString("PersistentKeepalive = 25\n")

		out = append(out, WgxrayClientConfig{
			DeviceIndex: i,
			IP:          addrs[i],
			PublicKey:   strings.TrimSpace(jsonString(d["pubKey"])),
			Config:      b.String(),
			Host:        endpointHost,
			Port:        inbound.Port,
		})
	}
	return out, nil
}
