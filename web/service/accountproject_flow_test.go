package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// The vless flow resolution is asymmetric on purpose: the INBOUND's declared value is
// gated on the transport, a stored per-membership override is not. These tests pin
// both halves, because the asymmetry looks like an oversight and was "fixed" once by
// moving the gate onto the resolved answer - which made the projection delete a flow
// that stored entries legitimately carried, and rolled the whole accounts migration
// back through verifyAccountsPass's round-trip check.

func vlessInbound(settings, stream string) *model.Inbound {
	return &model.Inbound{Protocol: model.VLESS, Settings: settings, StreamSettings: stream}
}

const (
	tcpReality = `{"network":"tcp","security":"reality"}`
	tcpTLS     = `{"network":"tcp","security":"tls"}`
	wsTLS      = `{"network":"ws","security":"tls"}`
)

// The inbound default is what gets mirrored onto EVERY account on the inbound, so a
// value the transport cannot carry has to be dropped there: ungated, one stray value
// in a stored blob turns one broken account into all of them.
func TestInboundVlessFlowIsGatedOnTheTransport(t *testing.T) {
	const withFlow = `{"flow":"xtls-rprx-vision","clients":[]}`

	for _, tc := range []struct {
		name, stream, want string
	}{
		{"reality over tcp carries it", tcpReality, "xtls-rprx-vision"},
		{"tls over tcp carries it", tcpTLS, "xtls-rprx-vision"},
		{"ws cannot carry it", wsTLS, ""},
		{"grpc cannot carry it", `{"network":"grpc","security":"tls"}`, ""},
		{"tcp without tls cannot carry it", `{"network":"tcp","security":"none"}`, ""},
		// Absent or unparseable stream settings answer no. Declining to project a
		// flow costs a working inbound nothing the operator cannot restore from the
		// form; projecting a wrong one breaks every account served by the inbound.
		{"no stream settings at all", "", ""},
		{"unparseable stream settings", "{not json", ""},
	} {
		got := inboundVlessFlow(vlessInbound(withFlow, tc.stream))
		if got != tc.want {
			t.Errorf("%s: flow = %q, want %q", tc.name, got, tc.want)
		}
	}

	// The legacy spelling folds down wherever it is accepted. xray-core takes exactly
	// "" and "xtls-rprx-vision", and at settings level a value it refuses takes the
	// WHOLE config down rather than one client.
	udp443 := `{"flow":"xtls-rprx-vision-udp443"}`
	if got := inboundVlessFlow(vlessInbound(udp443, tcpReality)); got != "xtls-rprx-vision" {
		t.Errorf("udp443 should fold to plain vision, got %q", got)
	}
	if got := inboundVlessFlow(vlessInbound(`{"clients":[]}`, tcpReality)); got != "" {
		t.Errorf("an inbound with no flow should resolve to empty, got %q", got)
	}
}

// A stored override is pre-existing per-account state. Re-rendering it must reproduce
// it byte for byte, or the migration's round-trip verification reports a projection
// bug and rolls back.
func TestResolveVlessFlowTrustsAStoredOverride(t *testing.T) {
	override := &model.AccountInbound{Flow: "xtls-rprx-vision"}

	// The case that rolled the migration back: an override on a transport the gate
	// would refuse. It is broken for that ONE account and was already broken before
	// any of this; deleting it here would change stored data, not fix anything.
	if got := resolveVlessFlow(vlessInbound(`{"clients":[]}`, wsTLS), override); got != "xtls-rprx-vision" {
		t.Errorf("a stored override must survive re-rendering on any transport, got %q", got)
	}
	if got := resolveVlessFlow(vlessInbound(`{"clients":[]}`, ""), override); got != "xtls-rprx-vision" {
		t.Errorf("a stored override must survive an inbound with no stream settings, got %q", got)
	}

	// The override still beats the inbound where both are set, and an empty one still
	// falls through to the inbound's gated value.
	both := vlessInbound(`{"flow":"xtls-rprx-vision"}`, tcpReality)
	if got := resolveVlessFlow(both, &model.AccountInbound{Flow: "xtls-rprx-vision"}); got != "xtls-rprx-vision" {
		t.Errorf("override should win, got %q", got)
	}
	if got := resolveVlessFlow(both, &model.AccountInbound{}); got != "xtls-rprx-vision" {
		t.Errorf("no override should inherit the inbound, got %q", got)
	}
	if got := resolveVlessFlow(vlessInbound(`{"flow":"xtls-rprx-vision"}`, wsTLS), &model.AccountInbound{}); got != "" {
		t.Errorf("no override on a transport that cannot carry flow should resolve to empty, got %q", got)
	}

	// The fold applies to an override too: it can hold the legacy spelling, and it
	// reaches the core by a different path from the inbound default. Safe where the
	// gate was not, because it rewrites a value the core would refuse into the one it
	// accepts rather than deleting a value the stored entry has.
	legacy := &model.AccountInbound{Flow: "xtls-rprx-vision-udp443"}
	if got := resolveVlessFlow(vlessInbound(`{"clients":[]}`, tcpReality), legacy); got != "xtls-rprx-vision" {
		t.Errorf("an override carrying udp443 should fold, got %q", got)
	}
}
