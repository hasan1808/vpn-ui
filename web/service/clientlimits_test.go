package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

func intp(v int) *int { return &v }

// The whole point of the per-client speed override is that it REPLACES the inbound's
// rate for that direction rather than competing with it. Feeding it to minNonZero as
// a third candidate looks equivalent and is not: most-restrictive-wins is the rule for
// ONE account seen on TWO inbounds, and applying it here would silently discard any
// override that RAISES an account above its inbound.
func TestResolveSpeedLimitRatesOverridesTheInbound(t *testing.T) {
	limited := &model.Inbound{SpeedLimitEnable: true, SpeedLimitDown: 1000}

	// The case a naive merge gets wrong: raised above the inbound.
	down, up := resolveSpeedLimitRates(limited, speedLimitClient{speedDown: intp(5000)})
	if down != kbpsToBps(5000) {
		t.Errorf("a raised override must win, got %d want %d", down, kbpsToBps(5000))
	}
	// Non-separate mode mirrors the inbound's down onto up, and a direction the client
	// did not mention keeps that mirrored value.
	if up != kbpsToBps(1000) {
		t.Errorf("an unmentioned direction must inherit, got %d want %d", up, kbpsToBps(1000))
	}

	// Lowered below the inbound, the ordinary case.
	if down, _ = resolveSpeedLimitRates(limited, speedLimitClient{speedDown: intp(200)}); down != kbpsToBps(200) {
		t.Errorf("a lowered override should apply, got %d", down)
	}

	// An explicit 0 is a real override meaning UNLIMITED in that direction, which is
	// the per-account exemption the IP cap cannot express. It must NOT read as
	// "inherit", or the field could never exempt anyone from a throttled inbound.
	if down, _ = resolveSpeedLimitRates(limited, speedLimitClient{speedDown: intp(0)}); down != 0 {
		t.Errorf("an explicit 0 should mean unlimited, got %d", down)
	}

	// nil in both directions is pure inheritance.
	down, up = resolveSpeedLimitRates(limited, speedLimitClient{})
	if down != kbpsToBps(1000) || up != kbpsToBps(1000) {
		t.Errorf("no override should inherit both directions, got %d/%d", down, up)
	}

	// An override on an inbound whose OWN limiter is off still applies. This is the
	// single most likely thing an operator will try, and an early "the inbound is not
	// limited, skip it" gate would drop it silently.
	unlimited := &model.Inbound{SpeedLimitEnable: false}
	if down, _ = resolveSpeedLimitRates(unlimited, speedLimitClient{speedDown: intp(300)}); down != kbpsToBps(300) {
		t.Errorf("an override on an unlimited inbound should still apply, got %d", down)
	}

	// A negative cannot arrive through the panel (validateClientLimits refuses it) but
	// can through an imported or hand-edited row. It must read as unlimited, never as
	// a negative token-bucket rate, which is not "unlimited" but "stalled".
	if down, _ = resolveSpeedLimitRates(limited, speedLimitClient{speedDown: intp(-5)}); down != 0 {
		t.Errorf("a negative override should read as unlimited, got %d", down)
	}
}

// Separate mode reads the inbound's two columns independently, and an override still
// replaces only the direction it names.
func TestResolveSpeedLimitRatesSeparateDirections(t *testing.T) {
	inb := &model.Inbound{
		SpeedLimitEnable: true, SpeedLimitSeparate: true,
		SpeedLimitDown: 1000, SpeedLimitUp: 500,
	}
	down, up := resolveSpeedLimitRates(inb, speedLimitClient{speedUp: intp(100)})
	if down != kbpsToBps(1000) {
		t.Errorf("download should be untouched, got %d", down)
	}
	if up != kbpsToBps(100) {
		t.Errorf("upload should take the override, got %d", up)
	}
}

// The device override may only ever LOWER the inbound's K. An account's tunnel
// addresses are laid out on a uniform stride of K (vpnAccountBlock), so a bigger block
// for one account runs straight into the next account's addresses and two customers
// silently share a tunnel IP. The clamp is enforced on READ so a value arriving by API
// cannot raise it either.
func TestResolveUserLimitOverrideOnlyLowers(t *testing.T) {
	const k = 10

	for _, tc := range []struct {
		name     string
		override *int
		want     int
	}{
		{"absent inherits the inbound", nil, k},
		{"lower wins", intp(3), 3},
		{"equal is the same as absent", intp(10), k},
		{"higher is capped at the inbound", intp(64), k},
		// 0 and negatives are not a way to ask for "unlimited" here: unlimited is not
		// expressible, because the block is K addresses wide whatever the account
		// wants. They read as "no override", which is the safe direction.
		{"zero inherits", intp(0), k},
		{"negative inherits", intp(-1), k},
	} {
		if got := resolveUserLimitOverride(k, tc.override); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

// The trap this guards against is not exotic, it is the common path. An absent key
// decodes to nil, and nil is a REAL value on these columns meaning "inherit", so
// without a presence test every write that does not carry the keys would silently
// clear the overrides: the enable toggle on the Clients page, a bulk operation, a
// traffic reset, any script posting a partial client.
func TestLimitOverridesSurviveAPartialClientWrite(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46401, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "cap@example.com", "enable": true},
	})
	svc.MigrationAccounts()

	account, err := svc.GetAccountByEmail("cap@example.com")
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	account.SpeedLimitDown = intp(512)
	account.SpeedLimitUp = intp(0) // an explicit exemption, which is not the same as nil
	account.UserLimitOverride = intp(3)
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save account: %v", err)
	}

	// A write that says nothing at all about the limits, which is what almost every
	// client write looks like.
	if _, err := svc.ApplyMemberships("cap@example.com", []int{vless.Id}, nil, true); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	after, err := svc.GetAccountByEmail("cap@example.com")
	if err != nil || after == nil {
		t.Fatalf("re-read account: %v", err)
	}
	if after.SpeedLimitDown == nil || *after.SpeedLimitDown != 512 {
		t.Errorf("download override = %v, want 512 carried through untouched", after.SpeedLimitDown)
	}
	if after.SpeedLimitUp == nil || *after.SpeedLimitUp != 0 {
		t.Errorf("upload override = %v, want an explicit 0 to survive as 0 and not become nil", after.SpeedLimitUp)
	}
	if after.UserLimitOverride == nil || *after.UserLimitOverride != 3 {
		t.Errorf("device override = %v, want 3 carried through untouched", after.UserLimitOverride)
	}
}

// The override has to reach the CLIENT ENTRY, not just the accounts table, because the
// entry is the only thing the enforcement paths ever read: loadSpeedLimitPolicies
// decodes speedLimitDown/speedLimitUp out of the inbound's settings blob, and the four
// device-cap clamp sites unmarshal userLimitOverride from the same place. Stored on the
// account alone, the feature saves a value, shows it back on the Clients page, and
// throttles nobody.
func TestLimitOverridesAreProjectedOntoTheClientEntry(t *testing.T) {
	svc := newAccountsDB(t)
	vless := seedInboundWithClients(t, model.VLESS, 46411, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": "cap2@example.com", "enable": true},
	})
	svc.MigrationAccounts()

	// An entry that never had an override must not grow the keys at all. Rendering
	// three nulls onto every existing client would fail the migration's own
	// round-trip verification, which is what this half guards.
	before := readClients(t, vless.Id)
	for _, k := range []string{"speedLimitDown", "speedLimitUp", "userLimitOverride"} {
		if _, present := before[0][k]; present {
			t.Errorf("an account with no override should not carry %q at all", k)
		}
	}

	account, err := svc.GetAccountByEmail("cap2@example.com")
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	account.SpeedLimitDown = intp(512)
	account.SpeedLimitUp = intp(0) // an explicit exemption, which must survive as 0
	account.UserLimitOverride = intp(3)
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save account: %v", err)
	}
	if _, err := svc.ProjectAccount(database.GetDB(), account.Id); err != nil {
		t.Fatalf("ProjectAccount: %v", err)
	}

	entry := readClients(t, vless.Id)[0]
	if got, _ := entry["speedLimitDown"].(float64); got != 512 {
		t.Errorf("entry speedLimitDown = %v, want 512", entry["speedLimitDown"])
	}
	got, present := entry["speedLimitUp"].(float64)
	if !present || got != 0 {
		t.Errorf("entry speedLimitUp = %v, want an explicit 0 rather than an absent key", entry["speedLimitUp"])
	}
	if got, _ := entry["userLimitOverride"].(float64); got != 3 {
		t.Errorf("entry userLimitOverride = %v, want 3", entry["userLimitOverride"])
	}

	// ...and clearing an override removes the key again, so the entry goes back to
	// looking exactly like one that never had it.
	account.SpeedLimitDown = nil
	account.SpeedLimitUp = nil
	account.UserLimitOverride = nil
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save cleared account: %v", err)
	}
	if _, err := svc.ProjectAccount(database.GetDB(), account.Id); err != nil {
		t.Fatalf("ProjectAccount after clearing: %v", err)
	}
	cleared := readClients(t, vless.Id)[0]
	for _, k := range []string{"speedLimitDown", "speedLimitUp", "userLimitOverride"} {
		if _, present := cleared[k]; present {
			t.Errorf("clearing the override should delete %q, not leave a null", k)
		}
	}
}
