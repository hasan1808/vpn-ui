package service

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

const (
	mb = 1 << 20
	gb = 1 << 30
)

// policy builds an enabled multiplier policy: past `after` bytes, count at `mult`.
func policy(after int64, mult float64) *model.Inbound {
	return &model.Inbound{
		TrafficMultiplierEnable: true,
		TrafficMultiplierAfter:  after,
		TrafficMultiplier:       mult,
	}
}

func TestMultiplyDelta(t *testing.T) {
	tests := []struct {
		name             string
		inb              *model.Inbound
		current          int64 // stored up+down before this delta
		up, down         int64 // raw delta
		wantUp, wantDown int64
	}{
		// Off / no-op cases must pass the delta through untouched.
		{"nil inbound", nil, 0, 100, 100, 100, 100},
		{"policy disabled", &model.Inbound{TrafficMultiplier: 2}, 0, 100, 100, 100, 100},
		{"multiplier of 1", policy(gb, 1), 2 * gb, 100, 100, 100, 100},
		{"multiplier below 1 is ignored", policy(gb, 0.5), 2 * gb, 100, 100, 100, 100},
		{"zero delta", policy(gb, 2), 2 * gb, 0, 0, 0, 0},

		// The user's example: 2x after 1 GB. 10 MB used past the threshold bills 20 MB.
		{"past threshold doubles", policy(gb, 2), gb, 0, 10 * mb, 0, 20 * mb},
		{"wholly below threshold", policy(gb, 2), 0, 5 * mb, 5 * mb, 5 * mb, 5 * mb},
		{"exactly at threshold", policy(gb, 2), gb, 1 * mb, 1 * mb, 2 * mb, 2 * mb},
		{"one byte below threshold", policy(gb, 2), gb - 1, 0, 1, 0, 1},

		// A delta straddling the threshold splits: 4 MB at 1x + 6 MB at 2x = 16 MB.
		{"straddles the threshold", policy(gb, 2), gb - 4*mb, 0, 10 * mb, 0, 16 * mb},
		{"straddle splits across directions", policy(gb, 2), gb - 4*mb, 5 * mb, 5 * mb, 8 * mb, 8 * mb},

		// Threshold 0 means weight from the very first byte.
		{"zero threshold weights everything", policy(0, 3), 0, 10 * mb, 20 * mb, 30 * mb, 60 * mb},

		// Fractional multipliers round rather than truncate.
		{"fractional multiplier", policy(0, 1.5), 0, 0, 100, 0, 150},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotUp, gotDown := multiplyDelta(tc.inb, tc.current, tc.up, tc.down)
			if gotUp != tc.wantUp || gotDown != tc.wantDown {
				t.Errorf("multiplyDelta(current=%d, up=%d, down=%d) = (%d, %d); want (%d, %d)",
					tc.current, tc.up, tc.down, gotUp, gotDown, tc.wantUp, tc.wantDown)
			}
		})
	}
}

// The feature rests on this property: because traffic counts 1:1 below the
// threshold, the stored counter tracks real bytes exactly up to the crossing
// point. That is what makes testing the stored counter against the threshold
// correct, and what lets the feature work without a raw-byte shadow column.
// If this ever fails, the threshold test itself has become circular.
func TestBilledEqualsRealBelowThreshold(t *testing.T) {
	const threshold = 100 * mb
	inb := policy(threshold, 2)

	var stored, real int64
	// Feed many small deltas (300 KiB up + 724 KiB down = 1 MiB) up to just under
	// the threshold.
	for real < threshold-mb {
		up, down := multiplyDelta(inb, stored, 300*1024, 724*1024)
		stored += up + down
		real += mb
		if stored != real {
			t.Fatalf("below threshold: stored=%d but real=%d; the counters must not diverge", stored, real)
		}
	}

	// The loop stops 1 MiB short, so this 10 MiB delta straddles the threshold: the
	// last 1 MiB below it counts once, the 9 MiB above it counts double.
	before := stored
	up, down := multiplyDelta(inb, stored, 0, 10*mb)
	stored += up + down
	if grew := stored - before; grew != 19*mb {
		t.Errorf("straddling delta billed as %d; want %d (1 MiB at 1x + 9 MiB at 2x)", grew, 19*mb)
	}

	// Now wholly past the threshold, every further byte is weighted.
	before = stored
	up, down = multiplyDelta(inb, stored, 0, 10*mb)
	stored += up + down
	if grew := stored - before; grew != 20*mb {
		t.Errorf("past the threshold 10 MiB billed as %d; want %d (2x)", grew, 20*mb)
	}
}

// The apportioning across up/down is cosmetic (only the sum is enforced), but it
// must never lose or invent bytes.
func TestMultiplyDeltaPreservesBilledSum(t *testing.T) {
	inb := policy(gb, 2)
	cases := []struct{ up, down int64 }{
		{0, 10 * mb}, {10 * mb, 0}, {3 * mb, 7 * mb}, {1, 1}, {1, 0}, {7777777, 3333333},
	}
	for _, c := range cases {
		gotUp, gotDown := multiplyDelta(inb, 2*gb, c.up, c.down)
		// Wholly past the threshold, so the billed sum is exactly 2x the raw sum.
		want := (c.up + c.down) * 2
		if got := gotUp + gotDown; got != want {
			t.Errorf("up=%d down=%d: billed sum = %d; want %d", c.up, c.down, got, want)
		}
		if gotUp < 0 || gotDown < 0 {
			t.Errorf("up=%d down=%d: negative split (%d, %d)", c.up, c.down, gotUp, gotDown)
		}
	}
}

// seedMultiplierDB builds a real SQLite with one policy inbound (2x past 1 GB) and
// one plain inbound, each with a client, and returns their emails.
func seedMultiplierDB(t *testing.T) (multipliedEmail, plainEmail string) {
	t.Helper()
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	multiplied := &model.Inbound{
		UserId: 1, Tag: "inbound-10001", Port: 10001, Protocol: model.VMESS, Enable: true,
		TrafficMultiplierEnable: true, TrafficMultiplierAfter: gb, TrafficMultiplier: 2,
	}
	plain := &model.Inbound{
		UserId: 1, Tag: "inbound-10002", Port: 10002, Protocol: model.VMESS, Enable: true,
		TrafficMultiplier: 1,
	}
	for _, ib := range []*model.Inbound{multiplied, plain} {
		if err := db.Create(ib).Error; err != nil {
			t.Fatalf("create inbound %s: %v", ib.Tag, err)
		}
	}

	multipliedEmail, plainEmail = "weighted@test", "normal@test"
	rows := []*xray.ClientTraffic{
		{InboundId: multiplied.Id, Email: multipliedEmail, Enable: true},
		{InboundId: plain.Id, Email: plainEmail, Enable: true},
	}
	for _, ct := range rows {
		if err := db.Create(ct).Error; err != nil {
			t.Fatalf("create client_traffic %s: %v", ct.Email, err)
		}
	}
	return multipliedEmail, plainEmail
}

func storedUpDown(t *testing.T, email string) int64 {
	t.Helper()
	var ct xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", email).First(&ct).Error; err != nil {
		t.Fatalf("read back %s: %v", email, err)
	}
	return ct.Up + ct.Down
}

// The three RADIUS teardown paths bypass AddTraffic and write raw SQL, so they are
// the easiest place for the multiplier to be silently missed. This drives the real
// helper against a real DB.
func TestFoldClientTrafficAppliesMultiplier(t *testing.T) {
	weighted, normal := seedMultiplierDB(t)

	// Below the threshold: billed 1:1 even under a policy.
	foldClientTraffic(weighted, "", 100*mb, 100*mb)
	if got := storedUpDown(t, weighted); got != 200*mb {
		t.Errorf("below threshold: stored %d; want %d (unweighted)", got, 200*mb)
	}

	// Straddle: 824 MiB left at 1x, then 200 MiB at 2x = 1224 MiB more.
	foldClientTraffic(weighted, "", 0, 1024*mb)
	if got, want := storedUpDown(t, weighted), int64(200*mb+1224*mb); got != want {
		t.Errorf("straddling the threshold: stored %d; want %d", got, want)
	}

	// Wholly past: doubled.
	foldClientTraffic(weighted, "", 0, 10*mb)
	if got, want := storedUpDown(t, weighted), int64(200*mb+1224*mb+20*mb); got != want {
		t.Errorf("past the threshold: stored %d; want %d", got, want)
	}

	// An inbound with no policy is untouched no matter how much it moves.
	foldClientTraffic(normal, "", 0, 5*gb)
	if got := storedUpDown(t, normal); got != 5*gb {
		t.Errorf("unpolicied inbound: stored %d; want %d (raw)", got, 5*gb)
	}

	// A fold for an unknown client must not error or invent a row.
	foldClientTraffic("ghost@test", "", 1*mb, 1*mb)
}

// The three columns must survive AutoMigrate and a save/load round-trip, and
// existing rows must default to a 1x multiplier rather than 0x (which would zero
// out everyone's accounting on upgrade).
func TestInboundMultiplierColumnsRoundTrip(t *testing.T) {
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	ib := &model.Inbound{
		UserId: 1, Tag: "inbound-20001", Port: 20001, Protocol: model.VMESS, Enable: true,
		TrafficMultiplierEnable: true, TrafficMultiplierAfter: 3 * gb, TrafficMultiplier: 2.5,
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create: %v", err)
	}
	var got model.Inbound
	if err := db.Where("id = ?", ib.Id).First(&got).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !got.TrafficMultiplierEnable || got.TrafficMultiplierAfter != 3*gb || got.TrafficMultiplier != 2.5 {
		t.Errorf("round-trip = (%v, %d, %v); want (true, %d, 2.5)",
			got.TrafficMultiplierEnable, got.TrafficMultiplierAfter, got.TrafficMultiplier, int64(3*gb))
	}

	// A row written without the policy (the shape every pre-upgrade row has) must
	// read back as a harmless no-op, never as a 0x multiplier.
	if err := db.Exec(`INSERT INTO inbounds (user_id, tag, port, protocol, enable) VALUES (1, 'inbound-20002', 20002, 'vmess', 1)`).Error; err != nil {
		t.Fatalf("insert legacy-shaped row: %v", err)
	}
	var legacy model.Inbound
	if err := db.Where("tag = ?", "inbound-20002").First(&legacy).Error; err != nil {
		t.Fatalf("read legacy row: %v", err)
	}
	if legacy.TrafficMultiplier != 1 {
		t.Errorf("legacy row multiplier = %v; want 1 (the column default)", legacy.TrafficMultiplier)
	}
	up, down := multiplyDelta(&legacy, 999*gb, 10*mb, 10*mb)
	if up != 10*mb || down != 10*mb {
		t.Errorf("legacy row must count raw; got (%d, %d)", up, down)
	}
}
