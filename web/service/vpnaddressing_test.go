package service

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// seedAddressedInbound creates an ENABLED inbound with an explicit pool. Enabled
// matters: BuildVpnEmailToIPMap only walks enabled inbounds, so a disabled one reports
// no addresses at all and every assertion below would pass vacuously.
func seedAddressedInbound(t *testing.T, protocol model.Protocol, port int, settings map[string]any) *model.Inbound {
	t.Helper()
	bs, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port,
		Protocol: protocol, Enable: true, Settings: string(bs),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create %s inbound: %v", protocol, err)
	}
	return inbound
}

func addressedClient(email string, slot int) map[string]any {
	return map[string]any{
		"id": email, "email": email, "password": "pw-" + email, "enable": true, "slot": slot,
	}
}

// The report must agree with the map the Xray config generator builds its source-IP
// routing rules from. If the two ever disagree, the endpoint is telling an operator to
// write a firewall rule for an address the data plane does not route.
func TestInboundAddressingMatchesTheRoutingMap(t *testing.T) {
	newInboundDB(t)

	inbound := seedAddressedInbound(t, model.L2TP, 12001, map[string]any{
		"ipRanges":  []string{"10.0.5.2-10.0.5.254"},
		"userLimit": 4,
		"clients": []any{
			addressedClient("alice@example.com", 0),
			addressedClient("bob@example.com", 1),
		},
	})

	report, ok := InboundAddressing(inbound)
	if !ok {
		t.Fatal("l2tp has an address pool; InboundAddressing refused it")
	}
	if got := report.UserLimit.Effective; got != 4 {
		t.Errorf("effective user limit = %d, want 4", got)
	}
	if !reflect.DeepEqual(report.Subnets, []string{"10.0.5"}) {
		t.Errorf("subnets = %v, want [10.0.5]", report.Subnets)
	}
	if report.Used != 2 {
		t.Errorf("used = %d, want 2", report.Used)
	}

	// Independently derived from the allocator's own primitive, so this pins the
	// numbers rather than restating whatever the report happened to produce.
	wantAlice := vpnAccountDeviceIPs([]string{"10.0.5"}, 0, 4)
	wantBob := vpnAccountDeviceIPs([]string{"10.0.5"}, 1, 4)
	if len(wantAlice) != 4 || len(wantBob) != 4 {
		t.Fatalf("fixture is wrong: %v %v", wantAlice, wantBob)
	}

	byEmail := map[string][]string{}
	for _, account := range report.Accounts {
		byEmail[account.Email] = account.Addresses
	}
	if !reflect.DeepEqual(byEmail["alice@example.com"], wantAlice) {
		t.Errorf("alice: got %v, want %v", byEmail["alice@example.com"], wantAlice)
	}
	if !reflect.DeepEqual(byEmail["bob@example.com"], wantBob) {
		t.Errorf("bob: got %v, want %v", byEmail["bob@example.com"], wantBob)
	}

	// ...and the same thing the routing map says, which is the actual contract.
	routing := BuildVpnEmailToIPMap()
	if !reflect.DeepEqual(routing["alice@example.com"], wantAlice) {
		t.Errorf("the routing map disagrees with the report: %v vs %v", routing["alice@example.com"], wantAlice)
	}
}

// The addresses come from a PANEL-WIDE map keyed by email, and one account can be on
// several inbounds. Without the per-inbound filter the l2tp report would tell an
// operator their account also answers on a wg-c address, which is true of the account
// but false of the inbound they asked about.
func TestInboundAddressingReportsOnlyItsOwnInbound(t *testing.T) {
	newInboundDB(t)

	const shared = "carol@example.com"
	l2tp := seedAddressedInbound(t, model.L2TP, 12010, map[string]any{
		"ipRanges":  []string{"10.0.9.2-10.0.9.254"},
		"userLimit": 1,
		"clients":   []any{addressedClient(shared, 0)},
	})
	wgc := seedAddressedInbound(t, model.WGC, 12011, map[string]any{
		"ipRanges":  []string{"10.7.9.2-10.7.9.254"},
		"userLimit": 1,
		"clients":   []any{addressedClient(shared, 0)},
	})

	// The account really is on both, so the panel-wide map has to carry both.
	routing := BuildVpnEmailToIPMap()
	if len(routing[shared]) < 2 {
		t.Fatalf("fixture is wrong: the shared account should hold 2 addresses, got %v", routing[shared])
	}

	for _, tc := range []struct {
		name     string
		inbound  *model.Inbound
		wantSub  string
		otherSub string
	}{
		{"l2tp", l2tp, "10.0.9", "10.7.9"},
		{"wg-c", wgc, "10.7.9", "10.0.9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, ok := InboundAddressing(tc.inbound)
			if !ok {
				t.Fatalf("%s was refused", tc.name)
			}
			if len(report.Accounts) != 1 {
				t.Fatalf("want 1 account, got %#v", report.Accounts)
			}
			got := report.Accounts[0].Addresses
			if len(got) == 0 {
				t.Fatalf("no address reported for the shared account")
			}
			for _, addr := range got {
				if !hasSubnetPrefix(addr, tc.wantSub) {
					t.Errorf("address %q is not in this inbound's pool %s", addr, tc.wantSub)
				}
				if hasSubnetPrefix(addr, tc.otherSub) {
					t.Errorf("address %q leaked in from the other inbound", addr)
				}
			}
		})
	}
}

func hasSubnetPrefix(addr, subnet string) bool {
	return len(addr) > len(subnet) && addr[:len(subnet)+1] == subnet+"."
}

// The User Limit resolution is the single most misread number in the settings JSON:
// absent is not 0, "no limit" is not 64, and wg-c/awg disagree with everything else.
// Reporting posted and effective side by side is the whole point of the field.
func TestInboundAddressingUserLimitResolution(t *testing.T) {
	newInboundDB(t)

	tests := []struct {
		name       string
		protocol   model.Protocol
		port       int
		settings   map[string]any
		wantK      int
		wantRule   string
		wantPosted *int
	}{
		{
			name:     "absent is a legacy single-device inbound, not no-limit",
			protocol: model.L2TP, port: 12020,
			settings: map[string]any{"ipRanges": []string{"10.0.20.2-10.0.20.254"}},
			wantK:    1, wantRule: "absent-legacy", wantPosted: nil,
		},
		{
			name:     "explicit 0 is a bounded block, NOT 64",
			protocol: model.L2TP, port: 12021,
			settings: map[string]any{"ipRanges": []string{"10.0.21.2-10.0.21.254"}, "userLimit": 0},
			wantK:    noLimitDevices, wantRule: "no-limit", wantPosted: intPtr(0),
		},
		{
			name:     "explicit 0 on wg-c IS the maximum, because there it only sizes a block",
			protocol: model.WGC, port: 12022,
			settings: map[string]any{"ipRanges": []string{"10.7.22.2-10.7.22.254"}, "userLimit": 0},
			wantK:    maxUserLimit, wantRule: "no-limit", wantPosted: intPtr(0),
		},
		{
			name:     "an ordinary value passes through",
			protocol: model.L2TP, port: 12023,
			settings: map[string]any{"ipRanges": []string{"10.0.23.2-10.0.23.254"}, "userLimit": 5},
			wantK:    5, wantRule: "explicit", wantPosted: intPtr(5),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inbound := seedAddressedInbound(t, tt.protocol, tt.port, tt.settings)
			report, ok := InboundAddressing(inbound)
			if !ok {
				t.Fatalf("%s was refused", tt.protocol)
			}
			if report.UserLimit.Effective != tt.wantK {
				t.Errorf("effective = %d, want %d", report.UserLimit.Effective, tt.wantK)
			}
			if report.UserLimit.Rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", report.UserLimit.Rule, tt.wantRule)
			}
			switch {
			case tt.wantPosted == nil && report.UserLimit.Posted != nil:
				t.Errorf("posted = %d, want absent", *report.UserLimit.Posted)
			case tt.wantPosted != nil && report.UserLimit.Posted == nil:
				t.Errorf("posted is absent, want %d", *tt.wantPosted)
			case tt.wantPosted != nil && *report.UserLimit.Posted != *tt.wantPosted:
				t.Errorf("posted = %d, want %d", *report.UserLimit.Posted, *tt.wantPosted)
			}
		})
	}
}

// A relay and an Xray-native protocol hand out no client address at all. Reporting an
// empty pool for them would read as "misconfigured" rather than "not applicable".
func TestInboundAddressingRefusesProtocolsWithNoPool(t *testing.T) {
	newInboundDB(t)

	for i, protocol := range []model.Protocol{model.MTPROTO, model.SSH, model.VMESS, model.ANYTLS} {
		inbound := seedAddressedInbound(t, protocol, 12040+i, map[string]any{"clients": []any{}})
		if _, ok := InboundAddressing(inbound); ok {
			t.Errorf("%s has no address pool but was reported as if it did", protocol)
		}
	}
}

// An inbound whose accounts cannot be parsed still has a pool worth reporting: dropping
// the whole report would make one malformed client entry look like "this inbound has no
// addressing", which is the opposite of the truth.
func TestInboundAddressingSurvivesUnreadableClients(t *testing.T) {
	newInboundDB(t)

	inbound := seedAddressedInbound(t, model.L2TP, 12050, map[string]any{
		"ipRanges": []string{"10.0.50.2-10.0.50.254"},
	})
	// Replace the client list with something GetClients cannot decode.
	inbound.Settings = `{"ipRanges":["10.0.50.2-10.0.50.254"],"clients":[{"email":{"not":"a string"}}]}`

	report, ok := InboundAddressing(inbound)
	if !ok {
		t.Fatal("the pool should still be reported")
	}
	if !reflect.DeepEqual(report.Subnets, []string{"10.0.50"}) {
		t.Errorf("subnets = %v, want [10.0.50]", report.Subnets)
	}
}

func TestVpnPoolOccupancy(t *testing.T) {
	newInboundDB(t)

	seedAddressedInbound(t, model.L2TP, 12060, map[string]any{
		"ipRanges": []string{"10.0.10.2-10.0.10.254"}, "clients": []any{},
	})
	seedAddressedInbound(t, model.L2TP, 12061, map[string]any{
		"ipRanges": []string{"10.0.2.2-10.0.2.254"}, "clients": []any{},
	})
	// A relay owns no address space and must not appear at all.
	seedAddressedInbound(t, model.SSH, 12062, map[string]any{"clients": []any{}})
	ovpn := seedAddressedInbound(t, model.OPENVPN, 12063, map[string]any{
		"ipRanges": []string{"10.2.4.2-10.2.4.254"}, "clients": []any{},
	})

	blocks := VpnPoolOccupancy()
	subnets := make([]string, 0, len(blocks))
	for _, b := range blocks {
		subnets = append(subnets, b.Subnet)
		if b.Protocol == model.SSH {
			t.Error("a relay protocol claimed address space")
		}
	}

	// Numeric order, not lexical: sorting these as strings puts 10.0.10 before 10.0.2,
	// which reads as corruption in a list an operator scans for a free block.
	want := []string{"10.0.2", "10.0.10", "10.2.4", "10.3.4"}
	if !reflect.DeepEqual(subnets, want) {
		t.Fatalf("occupancy = %v, want %v", subnets, want)
	}

	// The OpenVPN TCP mirror is held by the same inbound, and an operator who cannot
	// see it will eventually try to allocate over it.
	for _, b := range blocks {
		if b.Subnet == "10.3.4" && b.InboundId != ovpn.Id {
			t.Errorf("the TCP mirror is attributed to inbound %d, want %d", b.InboundId, ovpn.Id)
		}
	}
}
