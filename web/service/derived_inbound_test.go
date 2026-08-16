package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// An inbound whose Xray presence is DERIVED (a dokodemo for the VPN protocols, a paired
// socks inbound for the relays) must never take the live del/add API path in
// Add/UpdateInbound. The delete half succeeds because the derived inbound carries this
// inbound's tag, the add half cannot rebuild it, and the generated config still matches
// the running one so no restart repairs the gap.
//
// This is the regression guard for "enabling the speed limit on an mtproto inbound kills
// the backend until cores are restarted": mtproto and ssh were being treated as native
// Xray inbounds here.
func TestDerivedXrayInboundsSkipTheLiveApiPath(t *testing.T) {
	// Every protocol the panel terminates itself. A new one added to isVpnProtocol or
	// isRelayProtocol but forgotten here is the failure this list exists to catch.
	derived := []model.Protocol{
		model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT,
		model.SSTP, model.IKEV2, model.WGC, model.AWG, // dokodemo
		model.MTPROTO, model.SSH, // paired socks inbound
	}
	for _, p := range derived {
		if !hasDerivedXrayInbound(p) {
			t.Errorf("%q would take the live del/add API path: its derived inbound gets "+
				"deleted and cannot be re-added, killing the protocol until a restart "+
				"that an unchanged config never triggers", p)
		}
	}

	// The native Xray protocols must KEEP the API path: it is what applies their changes
	// without dropping every other inbound's connections.
	for _, p := range []model.Protocol{
		model.VMESS, model.VLESS, model.Trojan, model.Shadowsocks,
		model.HTTP, model.Mixed, model.WireGuard,
	} {
		if hasDerivedXrayInbound(p) {
			t.Errorf("%q is a native Xray inbound; forcing it onto the restart path costs "+
				"every inbound's live connections on each edit", p)
		}
	}
}

// The relays are the half that was wrong, so pin them independently of the VPN list:
// hasDerivedXrayInbound would still pass the test above if isRelayProtocol were folded
// into isVpnProtocol, which would then mislead every isVpnProtocol caller (addressing,
// nftables, RBridge) into treating a relay as a tunnel.
func TestRelayProtocolsAreNotVpnProtocols(t *testing.T) {
	for _, p := range []model.Protocol{model.MTPROTO, model.SSH} {
		if !isRelayProtocol(p) {
			t.Errorf("%q must be a relay: it egresses through a paired socks inbound", p)
		}
		if isVpnProtocol(p) {
			t.Errorf("%q is a relay, not a tunnel: it has no 10.x pool, no nftables "+
				"routing and no dokodemo, and isVpnProtocol callers assume all three", p)
		}
	}
}
