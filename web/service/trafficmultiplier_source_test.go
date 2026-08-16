package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// One account can now be served on several inbounds with DIFFERENT traffic
// multipliers, so "which inbound bills this byte" became a real question.
//
// The rule: bill at the multiplier of the inbound the bytes actually came from
// where that is knowable, and at the MAX across the account's memberships where
// it is not, so ambiguity over-bills rather than handing out free traffic.

func multiplierInbound(t *testing.T, protocol model.Protocol, port int, multiplier float64, clients []map[string]any) *model.Inbound {
	t.Helper()
	inbound := seedInboundWithClients(t, protocol, port, clients)
	err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", inbound.Id).
		Updates(map[string]any{
			"traffic_multiplier_enable": multiplier > 1,
			"traffic_multiplier":        multiplier,
			"traffic_multiplier_after":  0,
		}).Error
	if err != nil {
		t.Fatalf("set multiplier: %v", err)
	}
	inbound.TrafficMultiplierEnable = multiplier > 1
	inbound.TrafficMultiplier = multiplier
	return inbound
}

// A record naming its source inbound bills at THAT inbound's rate, even when the
// account's traffic row names a different one.
func TestBillingUsesTheSourceInboundNotTheHomeInbound(t *testing.T) {
	svc := newInboundDB(t)
	home := multiplierInbound(t, model.L2TP, 47101, 1, []map[string]any{
		{"id": "bob", "password": "pw", "email": "bob@example.com", "enable": true, "slot": float64(0)},
	})
	expensive := multiplierInbound(t, model.OPENVPN, 47102, 5, []map[string]any{
		{"id": "bob", "password": "pw", "email": "bob@example.com", "enable": true, "slot": float64(0)},
	})
	// The single row names the CHEAP inbound.
	seedTraffic(t, home.Id, "bob@example.com", 0, 0, 0, 0, true)

	const mb = int64(1024 * 1024)
	// 10 MB collected FROM the expensive inbound.
	_, _, _, _, _ = svc.AddTraffic(nil, []*xray.ClientTraffic{
		{Email: "bob@example.com", InboundId: expensive.Id, Up: 0, Down: 10 * mb},
	})

	var row xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", "bob@example.com").First(&row).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got, want := row.Up+row.Down, 50*mb; got != want {
		t.Errorf("billed %d bytes, want %d (5x, the SOURCE inbound's rate, not the home inbound's 1x)", got, want)
	}
	// AllTime stays raw: it is the record of bytes actually moved.
	if row.AllTime != 10*mb {
		t.Errorf("allTime = %d, want the raw %d", row.AllTime, 10*mb)
	}
}

// A record with no source (InboundId 0) is the Xray-native case: the core's
// counter has no inbound component, so there is genuinely nothing to attribute.
// It must take the MAX across memberships rather than the home inbound's rate.
func TestBillingFallsBackToMaxWhenSourceIsUnknown(t *testing.T) {
	svc := newInboundDB(t)
	cheap := multiplierInbound(t, model.VLESS, 47201, 1, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "bob@example.com", "enable": true},
	})
	multiplierInbound(t, model.Trojan, 47202, 4, []map[string]any{
		{"password": "pw", "email": "bob@example.com", "enable": true},
	})
	seedTraffic(t, cheap.Id, "bob@example.com", 0, 0, 0, 0, true)

	const mb = int64(1024 * 1024)
	_, _, _, _, _ = svc.AddTraffic(nil, []*xray.ClientTraffic{
		{Email: "bob@example.com", InboundId: 0, Up: 0, Down: 10 * mb},
	})

	var row xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", "bob@example.com").First(&row).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got, want := row.Up+row.Down, 40*mb; got != want {
		t.Errorf("billed %d bytes, want %d (max across memberships): under-billing here is free traffic", got, want)
	}
}

// A single-membership account must bill exactly as it always did.
func TestBillingUnchangedForSingleMembership(t *testing.T) {
	svc := newInboundDB(t)
	only := multiplierInbound(t, model.L2TP, 47301, 3, []map[string]any{
		{"id": "bob", "password": "pw", "email": "bob@example.com", "enable": true, "slot": float64(0)},
	})
	seedTraffic(t, only.Id, "bob@example.com", 0, 0, 0, 0, true)

	const mb = int64(1024 * 1024)
	_, _, _, _, _ = svc.AddTraffic(nil, []*xray.ClientTraffic{
		{Email: "bob@example.com", Up: 0, Down: 10 * mb},
	})

	var row xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", "bob@example.com").First(&row).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got, want := row.Up+row.Down, 30*mb; got != want {
		t.Errorf("billed %d, want %d", got, want)
	}
}

// maxMultiplierInbound must ignore inbounds whose policy is OFF: they bill 1:1
// whatever weight is stored on the row, so comparing their number would pick a
// rate that is never actually applied.
func TestMaxMultiplierInboundIgnoresDisabledPolicy(t *testing.T) {
	off := &model.Inbound{Id: 1, TrafficMultiplierEnable: false, TrafficMultiplier: 99}
	on := &model.Inbound{Id: 2, TrafficMultiplierEnable: true, TrafficMultiplier: 2}
	got := maxMultiplierInbound([]*model.Inbound{off, on})
	if got == nil || got.Id != 2 {
		t.Fatalf("picked %+v, want the inbound whose policy is actually on", got)
	}
	if maxMultiplierInbound([]*model.Inbound{off}) != nil {
		t.Error("an inbound with the policy off was chosen as the billing inbound")
	}
}

// SingleInboundIdByEmail reports 0 for an account on two inbounds of one
// protocol, which is the "unknown source" signal. Guessing one of the two would
// silently bill half the customer's traffic at the wrong rate.
func TestSingleInboundIdByEmailReportsAmbiguity(t *testing.T) {
	svc := newInboundDB(t)
	seedInboundWithClients(t, model.OPENVPN, 47401, []map[string]any{
		{"id": "bob", "password": "pw", "email": "bob@example.com", "enable": true, "slot": float64(0)},
		{"id": "solo", "password": "pw", "email": "solo@example.com", "enable": true, "slot": float64(1)},
	})
	second := &model.Inbound{
		UserId: 1, Tag: "openvpn-second", Port: 47402, Protocol: model.OPENVPN, Enable: true,
		Settings: `{"clients":[{"id":"bob","password":"pw","email":"bob@example.com","enable":true,"slot":0}]}`,
	}
	if err := database.GetDB().Create(second).Error; err != nil {
		t.Fatalf("create second inbound: %v", err)
	}

	got := svc.SingleInboundIdByEmail("openvpn")
	if got[accountKey("bob@example.com")] != 0 {
		t.Errorf("bob resolved to inbound %d, want 0: two openvpn inbounds serve them", got[accountKey("bob@example.com")])
	}
	if got[accountKey("solo@example.com")] == 0 {
		t.Error("an unambiguous account resolved to 0, so its bytes would needlessly take the max")
	}
}
