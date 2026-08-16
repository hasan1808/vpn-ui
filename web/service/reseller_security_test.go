package service

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// The bypasses in this file are the ones that let a reseller obtain traffic an
// admin never granted. Each is a hole that existed and was closed, so each test
// states the attack rather than the mechanism: a refactor that reopens one must
// fail here with the attack named.
//
// The invariant under all of them: a reseller can never end up able to move more
// bytes than AllowanceBytes, minus genuine refunds for capacity nobody used.

// A reseller must not be able to set an auto-renew period.
//
// `reset` is a number of DAYS after which autoRenewClients zeroes an account's
// counters, re-enables it and pushes its deadline forward, on a timer, forever,
// consulting no balance. Sell one gigabyte with reset=1 and the account is
// handed a fresh gigabyte every day for the rest of its life, charged once.
func TestResellerCannotSetAutoRenewPeriod(t *testing.T) {
	profile := &model.ResellerProfile{AllowExternalProxy: true}
	for _, reset := range []any{float64(1), float64(30), float64(-1)} {
		body := map[string]any{"clients": []any{map[string]any{
			"email": "sold", "totalGB": float64(gb), "reset": reset,
		}}}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		data := &model.Inbound{Settings: string(raw)}
		cm, settings, clients, err := postedClient(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyToSettings(data, profile, ChargeQuote{}, cm, settings, clients); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(data.Settings, "\"reset\"") {
			t.Errorf("reset=%v survived into the stored client: an unmetered renewal every period", reset)
		}
	}
}

// An admin's account must not be claimable by posting its email.
//
// AddInboundClient rejects a duplicate email, but it runs AFTER the reservation,
// and the reservation writes the ResellerClient row that OwnsClientEmail answers
// from. For the width of the failed create the reseller owned an admin's
// account, which a second concurrent request could edit or delete. Rollback
// closes that window afterwards, and afterwards is not a security boundary.
func TestResellerCannotClaimAnExistingEmail(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()

	// The victim as it really exists: a client inside an ADMIN's inbound
	// settings blob, which is where the panel's duplicate-email check looks.
	victim, err := json.Marshal(map[string]any{"clients": []any{map[string]any{
		"id": "uuid-victim", "email": "victim", "enable": true, "totalGB": float64(5 * gb),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.Inbound{
		Id: 1, UserId: 1, Enable: true, Remark: "admins", Protocol: model.VMESS,
		Port: 21001, Tag: "inbound-21001", Settings: string(victim),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&xray.ClientTraffic{
		InboundId: 1, Email: "victim", Enable: true, Total: 5 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}

	reseller := &model.User{Username: "claimer", Password: "x", Enable: true, IsReseller: true}
	if err := db.Create(reseller).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.ResellerProfile{
		UserId: reseller.Id, AllowanceBytes: 100 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{"clients": []any{map[string]any{
		"email": "victim", "totalGB": float64(gb),
	}}})
	data := &model.Inbound{Id: 1, Settings: string(body)}

	rs := &ResellerService{}
	if _, err := rs.PrepareClientCreate(reseller, data); err == nil {
		t.Fatal("claiming an admin's existing email was accepted")
	}
	// And the attempt must leave nothing behind: no ownership row to answer
	// OwnsClientEmail with, and no charge.
	var owned int64
	db.Model(&model.ResellerClient{}).Where("email = ?", "victim").Count(&owned)
	if owned != 0 {
		t.Error("a ResellerClient row was written for an account the reseller does not own")
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", reseller.Id).First(&p)
	if p.SpentBytes != 0 {
		t.Errorf("SpentBytes = %d; a refused create must not charge", p.SpentBytes)
	}
}

// Concurrent creates must not both fit into headroom that only covers one.
//
// Quote checks against a profile read earlier in the request, so two requests
// can see the same 10 GB free and each approve a 6 GB account. Only the debit
// statement itself can decide this atomically.
func TestResellerCannotOversellByRacing(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	if err := db.Create(&model.ResellerProfile{
		UserId: 9, AllowanceBytes: 10 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}

	const racers = 8
	var wg sync.WaitGroup
	ok := make([]bool, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 6 GB each: exactly one can fit inside 10 GB.
			ok[i] = addSpent(db, 9, 6*gb) == nil
		}(i)
	}
	wg.Wait()

	granted := 0
	for _, o := range ok {
		if o {
			granted++
		}
	}
	if granted != 1 {
		t.Errorf("%d of %d concurrent 6 GB debits were accepted against a 10 GB balance; want exactly 1", granted, racers)
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", 9).First(&p)
	if p.SpentBytes > p.AllowanceBytes {
		t.Errorf("SpentBytes %d exceeds AllowanceBytes %d: the reseller sold traffic nobody granted", p.SpentBytes, p.AllowanceBytes)
	}
}

// A refund must never be blocked by the headroom check that guards a debit.
// An over-sold reseller has to remain unwindable.
func TestRefundsAreNeverBlockedByTheBalanceGuard(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	if err := db.Create(&model.ResellerProfile{
		UserId: 11, AllowanceBytes: 1 * gb, SpentBytes: 50 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := addSpent(db, 11, -20*gb); err != nil {
		t.Fatalf("refund refused on an over-spent profile: %v", err)
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", 11).First(&p)
	if p.SpentBytes != 30*gb {
		t.Errorf("SpentBytes = %d; want %d", p.SpentBytes, 30*gb)
	}
}

// An unlimited reseller is exempt from the headroom check but still accrues, so
// a later switch to a limited plan accounts for what they already sold.
func TestUnlimitedResellerStillAccrues(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	if err := db.Create(&model.ResellerProfile{
		UserId: 12, AllowanceBytes: 0, Unlimited: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := addSpent(db, 12, 500*gb); err != nil {
		t.Fatalf("unlimited debit refused: %v", err)
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", 12).First(&p)
	if p.SpentBytes != 500*gb {
		t.Errorf("SpentBytes = %d; want the debit to accrue even while unlimited", p.SpentBytes)
	}
}

// depletedAfter must answer the same question the enforcement job asks, or the
// two disagree about which accounts are allowed to run.
func TestDepletedAfterMatchesTheEnforcementPredicate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		up, down  int64
		total     int64
		wantSpent bool
	}{
		{"unlimited is never depleted", 900 * gb, 900 * gb, 0, false},
		{"under the limit", 1 * gb, 1 * gb, 5 * gb, false},
		{"exactly at the limit counts as spent", 2 * gb, 3 * gb, 5 * gb, true},
		{"over the limit", 5 * gb, 5 * gb, 5 * gb, true},
		{"a raised quota revives it", 2 * gb, 3 * gb, 50 * gb, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct := &xray.ClientTraffic{Up: tc.up, Down: tc.down}
			if got := depletedAfter(ct, tc.total); got != tc.wantSpent {
				t.Errorf("depletedAfter = %v; want %v", got, tc.wantSpent)
			}
		})
	}
	if depletedAfter(nil, 5*gb) {
		t.Error("a missing traffic row must not read as depleted")
	}
}

// The zero-quota and negative-quota refusals are the two cheapest ways to mint
// traffic, so they are asserted here as well as in the ledger tests: this file
// is what someone reads when asking "what stops a reseller cheating".
func TestQuoteRefusesTheFreeTrafficShapes(t *testing.T) {
	limited := model.ResellerProfile{AllowanceBytes: 100 * gb}
	if _, err := Quote(QuoteInput{Profile: limited, Create: true, NewTotal: 0}); !errors.Is(err, ErrUnlimitedAccount) {
		t.Errorf("err = %v; an unlimited ACCOUNT out of a limited balance must be refused", err)
	}
	if _, err := Quote(QuoteInput{Profile: limited, Create: true, NewTotal: -5 * gb}); !errors.Is(err, ErrInvalidQuota) {
		t.Errorf("err = %v; a negative quota prices as a negative charge, which pays the reseller", err)
	}
	unlimited := model.ResellerProfile{Unlimited: true}
	if _, err := Quote(QuoteInput{Profile: unlimited, Create: true, NewTotal: -5 * gb}); !errors.Is(err, ErrInvalidQuota) {
		t.Errorf("err = %v; a negative quota must be refused for an unlimited reseller too", err)
	}
	// Zeroing an account that already carries a charge is the refund-and-uncap
	// path: the flag is read at quote time, so a moment of being unlimited must
	// not be enough to keep the traffic AND the refund.
	sold := model.ResellerProfile{Unlimited: true}
	if _, err := Quote(QuoteInput{
		Profile: sold, OldTotal: 100 * gb, NewTotal: 0, OldCharged: 100 * gb,
	}); !errors.Is(err, ErrUnlimitedAccount) {
		t.Errorf("err = %v; an account holding a charge must never be zeroed", err)
	}
}

// A delete refunds ONLY what the customer never used, on every path.
//
// The trap this defends: deleting a client runs DelClientStat, which removes the
// client_traffics row that holds AllTime. A refund priced after the delete reads
// consumption as zero and hands back the entire charge, so a reseller could sell
// 10 GB, let the customer spend all of it, delete the account and get all 10 GB
// back. Repeat for unlimited free traffic.
//
// Which is why RefundDeleted takes the lifetime figure as an ARGUMENT: it must be
// captured while the row that proves it still exists.
func TestDeleteRefundsOnlyUnusedTraffic(t *testing.T) {
	for _, tc := range []struct {
		name            string
		charged, base   int64
		allTimeAtDelete int64
		known           bool
		wantRefund      int64
	}{
		{"nothing used refunds the whole charge", 10 * gb, 0, 0, true, 10 * gb},
		{"half used refunds half", 10 * gb, 0, 4 * gb, true, 6 * gb},
		{"fully used refunds nothing", 10 * gb, 0, 10 * gb, true, 0},
		{"over-used refunds nothing, never negative", 10 * gb, 0, 25 * gb, true, 0},
		{"consumption counts from the charge, not the account's whole life", 10 * gb, 100 * gb, 103 * gb, true, 7 * gb},
		{"a lost snapshot withholds the refund rather than inventing one", 10 * gb, 0, 0, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newInboundDB(t)
			db := database.GetDB()
			if err := db.Create(&model.ResellerProfile{
				UserId: 3, AllowanceBytes: 100 * gb, SpentBytes: 40 * gb,
			}).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Create(&model.ResellerClient{
				Email: "sold", InboundId: 1, UserId: 3,
				ChargedBytes: tc.charged, AllTimeBase: tc.base,
			}).Error; err != nil {
				t.Fatal(err)
			}

			rs := &ResellerService{}
			if err := rs.RefundDeleted("sold", tc.allTimeAtDelete, tc.known); err != nil {
				t.Fatalf("RefundDeleted: %v", err)
			}
			var p model.ResellerProfile
			db.Model(&model.ResellerProfile{}).Where("user_id = ?", 3).First(&p)
			got := 40*gb - p.SpentBytes
			if got != tc.wantRefund {
				t.Errorf("refund = %d; want %d", got, tc.wantRefund)
			}
			// The ownership row must go with the account either way, or a recycled
			// email inherits a charge that is no longer real.
			var left int64
			db.Model(&model.ResellerClient{}).Where("email = ?", "sold").Count(&left)
			if left != 0 {
				t.Error("the ownership row outlived the account it belonged to")
			}
		})
	}
}

// UsageSnapshot is the thing that has to be taken BEFORE a delete, so prove it
// reads what the refund needs and tolerates an account with no row at all.
func TestUsageSnapshotReadsLifetimeTraffic(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	for _, ct := range []xray.ClientTraffic{
		{InboundId: 1, Email: "a", AllTime: 7 * gb, Up: 1 * gb, Down: 1 * gb},
		{InboundId: 1, Email: "b", AllTime: 0},
	} {
		if err := db.Create(&ct).Error; err != nil {
			t.Fatal(err)
		}
	}
	rs := &ResellerService{}
	snap, err := rs.UsageSnapshot([]string{"a", "b", "never-existed"})
	if err != nil {
		t.Fatal(err)
	}
	// AllTime, not Up+Down: a reset zeroes the counters but not the lifetime
	// record, and pricing a refund off the resettable pair would let a reset
	// launder consumed bytes back into refundable balance.
	if snap[emailKey("a")] != 7*gb {
		t.Errorf("a = %d; want the lifetime figure %d", snap[emailKey("a")], 7*gb)
	}
	if _, ok := snap[emailKey("never-existed")]; ok {
		t.Error("an account with no traffic row must be absent, which reads as zero usage")
	}
	if used, known, err := rs.UsageOf("a"); err != nil || !known || used != 7*gb {
		t.Errorf("UsageOf = %d, known=%v, %v; want %d known", used, known, err, 7*gb)
	}
	if _, known, err := rs.UsageOf("never-existed"); err != nil || known {
		t.Error("an account with no traffic row must report its usage as UNKNOWN, which withholds the refund")
	}
}

// Undoing a deduct must never be blocked by the headroom guard.
//
// A deduct refunds, so its rollback DEBITS. Routed through the guard, an
// allowance an admin lowered in between refuses the unwind and the reseller
// keeps a refund for a deduct that never landed: the guard causing the exact
// leak it exists to stop.
func TestRollbackOfADeductIsNeverRefused(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	if err := db.Create(&model.ResellerProfile{
		UserId: 21, AllowanceBytes: 3 * gb, SpentBytes: 5 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.ResellerClient{
		Email: "sold", InboundId: 1, UserId: 21, ChargedBytes: 5 * gb,
	}).Error; err != nil {
		t.Fatal(err)
	}
	rs := &ResellerService{}
	// A deduct that refunded 5 GB, now being unwound: the debit is larger than
	// the (already exceeded) allowance allows.
	err := rs.Rollback(ChargeTicket{
		Active: true, UserId: 21, Email: "sold",
		Quote:       ChargeQuote{DeltaSpent: -5 * gb, NewCharged: 0},
		PrevCharged: 5 * gb,
	})
	if err != nil {
		t.Fatalf("rollback refused: %v", err)
	}
	var p model.ResellerProfile
	db.Model(&model.ResellerProfile{}).Where("user_id = ?", 21).First(&p)
	if p.SpentBytes != 10*gb {
		t.Errorf("SpentBytes = %d; want the deduct fully unwound to %d", p.SpentBytes, 10*gb)
	}
	var rc model.ResellerClient
	db.Model(&model.ResellerClient{}).Where("email = ?", "sold").First(&rc)
	if rc.ChargedBytes != 5*gb {
		t.Errorf("ChargedBytes = %d; want the previous charge restored", rc.ChargedBytes)
	}
}

// Switching a depleted account back on is a traffic grant whichever verb does
// it, so unfreeze is filtered exactly like enable. Exempting it because it
// "only restores a deadline" ignored that it writes enable=true as well.
func TestUnfreezeCannotReviveADepletedAccount(t *testing.T) {
	for _, op := range []string{"enable", "unfreeze"} {
		t.Run(op, func(t *testing.T) {
			newInboundDB(t)
			db := database.GetDB()
			for _, ct := range []xray.ClientTraffic{
				{InboundId: 1, Email: "spent", Total: 5 * gb, Up: 3 * gb, Down: 2 * gb},
				{InboundId: 1, Email: "healthy", Total: 5 * gb, Up: 1 * gb, Down: 0},
			} {
				if err := db.Create(&ct).Error; err != nil {
					t.Fatal(err)
				}
			}
			req := &BulkClientUpdateRequest{Op: op, Targets: []BulkClientTarget{
				{InboundId: 1, Email: "spent"}, {InboundId: 1, Email: "healthy"},
			}}
			rs := &ResellerService{}
			if err := rs.dropDepletedTargets(req); err != nil {
				t.Fatal(err)
			}
			if len(req.Targets) != 1 || req.Targets[0].Email != "healthy" {
				t.Errorf("targets = %+v; the depleted account must be dropped and the healthy one kept", req.Targets)
			}
		})
	}
}
