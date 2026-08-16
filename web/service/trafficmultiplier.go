package service

import (
	"errors"
	"math"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

// Traffic Multiplier: a per-inbound policy that weights a client's usage once it
// passes a threshold. Below the threshold traffic counts 1:1; past it, each byte
// counts TrafficMultiplier times against the client's quota. Protocol-agnostic:
// it lives at the accounting layer, below every protocol's collector.
//
// Why testing the stored counter against the threshold is exact, not circular:
// with billed(real) = real for real <= T, the stored counter equals real bytes
// right up to the crossing point, so `stored >= T` iff `real >= T`. Past the
// crossing the two diverge, but by then the answer no longer depends on which is
// read. That is what keeps this to three columns with no raw-byte shadow counter.
//
// The multiplier is applied at exactly two choke points, addClientTraffic (the 10s
// collection tick) and foldClientTraffic (the RADIUS teardown paths), and nowhere
// else. Applying it inside a protocol collector as well would double-multiply.

// MaxTrafficMultiplier bounds the weight. Far above any plausible billing policy,
// and far below the point where one tick's bytes times the multiplier could
// overflow int64 (a 10s tick at 10Gbps is ~1.2e10 bytes; 1e13 leaves six orders of
// headroom under int64's 9.2e18).
const MaxTrafficMultiplier = 1000

// validMultiplier reports whether m is a usable weight.
//
// NaN is the dangerous case and the reason this is a named check rather than an
// inline comparison: `NaN <= 1` is FALSE, so a bare `m <= 1` guard lets NaN
// straight through, and int64(NaN) is MinInt64. That drives a client's counter to
// roughly -4.6e18, and the enforcement predicate (`up + down >= total`) is then
// false forever, so the account can never be quota-disabled again and its counter
// is unrecoverable. Inf and any value large enough to overflow int64 do the same.
func validMultiplier(m float64) bool {
	return !math.IsNaN(m) && !math.IsInf(m, 0) && m > 1 && m <= MaxTrafficMultiplier
}

// multiplyDelta weights one raw byte delta according to inb's policy.
// currentUpDown is the client's stored up+down BEFORE this delta is applied.
// Returns the deltas unchanged when the policy is off, so callers can call it
// unconditionally.
func multiplyDelta(inb *model.Inbound, currentUpDown, deltaUp, deltaDown int64) (int64, int64) {
	// Saves are validated (validateInboundConfig), but this is the last line of
	// defence and it must hold for a row that arrived some other way: an imported
	// DB, a hand-edited SQLite file, a future caller. Billing raw is always safe;
	// billing NaN is unrecoverable.
	if inb == nil || !inb.TrafficMultiplierEnable || !validMultiplier(inb.TrafficMultiplier) {
		return deltaUp, deltaDown
	}
	raw := deltaUp + deltaDown
	if raw <= 0 {
		return deltaUp, deltaDown
	}
	if currentUpDown < 0 {
		currentUpDown = 0
	}
	// Bytes this delta still gets at 1:1 before it crosses the threshold. A delta
	// that straddles the threshold is split: the part below counts once, the rest
	// is weighted.
	pre := inb.TrafficMultiplierAfter - currentUpDown
	if pre < 0 {
		pre = 0
	}
	if pre >= raw {
		return deltaUp, deltaDown // wholly below the threshold
	}
	billed := pre + int64(math.Round(float64(raw-pre)*inb.TrafficMultiplier))
	// Apportion the billed total back across the two directions so their ratio stays
	// honest in reporting. Only the sum is ever enforced, so the split is cosmetic;
	// the remainder goes to Down to keep up+down == billed exactly.
	up := int64(math.Round(float64(billed) * (float64(deltaUp) / float64(raw))))
	return up, billed - up
}

// multiplierColumns is the minimal column set multiplyDelta needs. Selecting it
// explicitly keeps the 10s tick from loading every inbound's Settings JSON blob.
var multiplierColumns = []string{"id", "traffic_multiplier_enable", "traffic_multiplier_after", "traffic_multiplier"}

// Which inbound's multiplier bills a byte, now that one account can be on several.
//
// The rule is: bill at the multiplier of the inbound the bytes ACTUALLY came
// from. Where that is knowable it is used directly. Where it is not, the highest
// multiplier across the account's memberships is used instead, so the ambiguity
// can only ever over-bill, never hand out free traffic.
//
// It is knowable for the nine pool VPN protocols and the two relays: their bytes
// are counted per tunnel address (nftables) or per account by a single relay
// daemon, and both resolve to one inbound. The collectors stamp InboundId on the
// record they emit.
//
// It is NOT knowable for the Xray-native protocols, and that is a property of the
// core rather than something this code can plumb. Xray's per-account counter is
// named "user>>><email>>>>traffic>>>uplink" with NO inbound component (xray/api.go),
// so an account on vless AND trojan gets ONE number covering both. There is
// nothing to attribute. Rather than pretend, those records arrive with InboundId
// 0 and take the max.

// anyMultiplierEnabled reports whether ANY inbound on the panel weights traffic.
//
// It gates the membership resolution in addClientTraffic, which is a
// settings-JSON scan over every inbound on a 10s tick. When no inbound has the
// policy on, the answer cannot depend on which inbound bills a byte, so the scan
// is pure waste and the tick costs exactly what it did before this feature.
//
// Asked of the whole table rather than of the inbounds already loaded, and that
// distinction is the whole point: the inbound that would change the answer is
// precisely the one NOT yet loaded (an account's other membership). Gating on the
// loaded set instead silently skipped the lookup exactly when it mattered and
// billed the account at its home inbound's rate.
//
// One indexed COUNT over a narrow column, with no JSON parsed.
func anyMultiplierEnabled(tx *gorm.DB) bool {
	var count int64
	if err := tx.Model(model.Inbound{}).
		Where("traffic_multiplier_enable = ?", true).
		Count(&count).Error; err != nil {
		// Cannot tell, so assume yes: doing the extra work is a slow tick, while
		// skipping it when it was needed is a mis-billed account.
		return true
	}
	return count > 0
}

// maxMultiplierInbound returns the member inbound with the highest effective
// multiplier, for records whose source cannot be attributed.
//
// Ordering by the multiplier is only meaningful among inbounds that HAVE one
// enabled; an inbound with the policy off bills 1:1 whatever its stored weight,
// so it is skipped rather than compared.
func maxMultiplierInbound(candidates []*model.Inbound) *model.Inbound {
	var best *model.Inbound
	for _, inb := range candidates {
		if inb == nil || !inb.TrafficMultiplierEnable || !validMultiplier(inb.TrafficMultiplier) {
			continue
		}
		if best == nil || inb.TrafficMultiplier > best.TrafficMultiplier {
			best = inb
		}
	}
	return best
}

// billingInbound picks the inbound whose multiplier applies to one collected
// record: its stamped source if it has one, otherwise the max across the
// account's memberships.
func billingInbound(byID map[int]*model.Inbound, sourceInboundId int, memberIds []int) *model.Inbound {
	if sourceInboundId != 0 {
		if inb, ok := byID[sourceInboundId]; ok {
			return inb
		}
	}
	candidates := make([]*model.Inbound, 0, len(memberIds))
	for _, id := range memberIds {
		if inb, ok := byID[id]; ok {
			candidates = append(candidates, inb)
		}
	}
	return maxMultiplierInbound(candidates)
}

// loadMultiplierInbounds batch-loads every inbound whose multiplier could apply
// this tick, keyed by inbound id. One query for the whole tick.
//
// It takes several id sources because the inbound that BILLS a byte is no longer
// necessarily the one on the client's row: the collected record may name the
// inbound it came from, and an unattributable record needs every inbound the
// account is a member of so the max can be taken across them.
func loadMultiplierInbounds(tx *gorm.DB, idSets ...[]int) (map[int]*model.Inbound, error) {
	ids := make([]int, 0)
	seen := make(map[int]struct{})
	for _, set := range idSets {
		for _, id := range set {
			if id == 0 {
				continue
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var inbounds []*model.Inbound
	err := tx.Model(model.Inbound{}).Select(multiplierColumns).Where("id IN (?)", ids).Find(&inbounds).Error
	if err != nil {
		return nil, err
	}
	byID := make(map[int]*model.Inbound, len(inbounds))
	for _, ib := range inbounds {
		byID[ib.Id] = ib
	}
	return byID, nil
}

// foldClientTraffic adds a torn-down session's final bytes to a client's counters,
// applying the owning inbound's traffic multiplier.
//
// The RADIUS teardown paths (acct-stop, rbridge reconcile, user-limit evict) flush
// bytes outside the 10s collection tick, so they need the multiplier applied here
// or that traffic bills at 1:1 forever. Deciding where the delta sits relative to
// the threshold needs the current counter, so unlike the bare `up = up + ?` this
// replaces, it is a read-modify-write, hence the transaction.
// protocol names where the torn-down session was served, so the bytes bill at
// THAT inbound's multiplier rather than at whichever inbound the account's single
// client_traffics row happens to name. Empty falls back to the max across the
// account's memberships, which over-bills rather than under-bills.
func foldClientTraffic(email, protocol string, up, down int64) {
	if email == "" || (up <= 0 && down <= 0) {
		return
	}
	db := database.GetDB()
	if db == nil {
		return
	}

	// Resolved outside the transaction: it is a read-only lookup over the handful
	// of inbounds of one protocol, and holding the write transaction open across
	// it would widen the window on the 10s tick for no benefit.
	sourceInboundId := 0
	if protocol != "" {
		inboundService := InboundService{}
		sourceInboundId = inboundService.SingleInboundIdByEmail(protocol)[accountKey(email)]
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		var ct xray.ClientTraffic
		err := tx.Model(xray.ClientTraffic{}).Where("email = ?", email).First(&ct).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil // no row to bill, same as the plain UPDATE matching nothing
		}
		if err != nil {
			return err
		}
		billedUp, billedDown := up, down
		billingId := sourceInboundId
		if billingId == 0 {
			billingId = ct.InboundId
		}
		if billingId != 0 {
			var inb model.Inbound
			err := tx.Model(model.Inbound{}).Select(multiplierColumns).
				Where("id = ?", billingId).First(&inb).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if err == nil {
				billedUp, billedDown = multiplyDelta(&inb, ct.Up+ct.Down, up, down)
			}
		}
		// all_time takes the RAW delta while up/down take the billed one, matching
		// addClientTraffic. It is written here rather than left alone because the
		// startup backfill (MigrationRequirements) sets all_time = up+down for any
		// row still at 0, which for a client whose traffic only ever arrived through
		// this path would seed the lifetime record with MULTIPLIED bytes.
		return tx.Exec(
			"UPDATE client_traffics SET up = up + ?, down = down + ?, all_time = COALESCE(all_time, 0) + ? WHERE email = ?",
			billedUp, billedDown, up+down, email).Error
	})
	if err != nil {
		logger.Warning("fold client traffic for ", email, ": ", err)
	}
}
