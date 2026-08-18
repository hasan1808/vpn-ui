package service

import (
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

// Finishing the attribution Xray leaves unfinished.
//
// Xray's per-account counter is named "user>>><email>>>>traffic>>>{up,down}" with no
// inbound in it, so a record collected from the core says how much an account moved
// and nothing about where. Everything downstream of that - the per-inbound usage
// figure on the Clients page, which membership's lamp lights up, which inbound's
// traffic multiplier bills the bytes - then has nothing to work with, and an account
// on ten inbounds was reported as using, and being online on, all ten of them.
//
// The core cannot be made to say it (the stat name is the core's, not the panel's),
// but it does not have to: the answer is usually forced by what else is true in the
// same tick.
//
//  1. Only an inbound Xray TERMINATES can produce a user stat at all. The nine pool
//     VPN protocols reach the core through a dokodemo-door with no user identity on
//     it, so bytes on that record cannot be theirs, however busy those inbounds are.
//     That leaves the account's Xray-native inbounds plus the two relays, whose
//     paired socks inbound authenticates by email.
//
//  2. When exactly ONE of those is left, the record belongs to it. That is not a
//     guess: no other inbound of that account is capable of having produced it.
//
//  3. When several are left, the SAME tick's per-inbound totals decide. An inbound
//     that moved no bytes at all this tick moved none of this account's, so a
//     candidate whose tag is quiet is out. One candidate still standing is the
//     answer; two or more stays unattributed, and the page goes on saying "shared"
//     rather than picking one.
//
// What stays unattributed still reaches the account total, exactly as before: this
// only decides whether the bytes ALSO land in the per-inbound breakdown. The failure
// mode is a figure that reads "shared", never a lost byte.

// coreCandidate is one inbound an account's core-counted bytes could have come
// through.
type coreCandidate struct {
	Id       int
	Tag      string
	Protocol model.Protocol
	Email    string
}

// attributeCoreRecords stamps the source inbound onto the core-counted records that
// arrived without one, in place.
//
// inboundTraffics is the same tick's per-inbound totals (the other half of the one
// QueryStats call these records came from), and is what makes rule 3 above possible.
// A nil one is fine: the caller may have collected client traffic without it, and
// then only the unambiguous rules 1-2 apply.
//
// Best-effort by design. Every failure path leaves the records exactly as they
// arrived, which is the behaviour that shipped before any of this existed.
func attributeCoreRecords(tx *gorm.DB, inboundTraffics []*xray.Traffic, records []*xray.ClientTraffic) {
	if tx == nil {
		return
	}

	// Only records that (a) came from the core, so their bytes really did enter
	// through an Xray-terminated inbound, and (b) name no inbound yet. A collector
	// that already knows its source is never second-guessed.
	pending := map[string][]*xray.ClientTraffic{}
	for _, record := range records {
		if record == nil || !record.CoreCounted || record.InboundId != 0 {
			continue
		}
		if record.Up+record.Down <= 0 {
			// Nothing to attribute, and stamping it would light a membership's lamp
			// for an account that moved no bytes.
			continue
		}
		key := accountKey(record.Email)
		if key == "" {
			continue
		}
		pending[key] = append(pending[key], record)
	}
	if len(pending) == 0 {
		return
	}

	keys := make([]string, 0, len(pending))
	for key := range pending {
		keys = append(keys, key)
	}

	// The memberships, straight off account_inbounds rather than by scanning every
	// inbound's settings JSON: this runs on every traffic tick, and the join is two
	// indexed lookups where the scan is the whole table.
	var rows []coreCandidate
	err := tx.Table("account_inbounds").
		Select("inbounds.id AS id, inbounds.tag AS tag, inbounds.protocol AS protocol, "+
			"LOWER(TRIM(accounts.email)) AS email").
		Joins("JOIN accounts ON accounts.id = account_inbounds.account_id").
		Joins("JOIN inbounds ON inbounds.id = account_inbounds.inbound_id").
		Where("LOWER(TRIM(accounts.email)) IN (?)", keys).
		Scan(&rows).Error
	if err != nil {
		logger.Warning("per-inbound attribution: cannot resolve memberships, leaving this tick's core traffic unattributed: ", err)
		return
	}

	candidates := map[string][]coreCandidate{}
	for _, row := range rows {
		// Rule 1: a pool VPN inbound cannot have produced a user stat, so it is not a
		// candidate no matter what its own counters say.
		if isVpnProtocol(row.Protocol) {
			continue
		}
		candidates[row.Email] = append(candidates[row.Email], row)
	}

	// Rule 3's evidence: which inbounds moved anything at all this tick.
	active := map[string]bool{}
	for _, traffic := range inboundTraffics {
		if traffic != nil && traffic.IsInbound && traffic.Up+traffic.Down > 0 {
			active[traffic.Tag] = true
		}
	}

	for key, pendingRecords := range pending {
		inboundId := attributableInbound(candidates[key], active)
		if inboundId == 0 {
			continue
		}
		for _, record := range pendingRecords {
			record.InboundId = inboundId
		}
	}
}

// attributableInbound applies rules 2 and 3 to one account's candidates, returning 0
// for "still ambiguous".
func attributableInbound(candidates []coreCandidate, active map[string]bool) int {
	switch len(candidates) {
	case 0:
		// No memberships to attribute with. Either the accounts layer has not been
		// migrated on this panel, or the client lives in an inbound's settings without
		// a membership row; both are the pre-existing unattributed case.
		return 0
	case 1:
		// Rule 2. Deliberately NOT also requiring the tag to be active: inbound-level
		// stats can be absent (a tick collected without them, an inbound whose totals
		// were reset in between), and that must not undo an answer that is already
		// forced by there being nothing else it could be.
		return candidates[0].Id
	}
	if len(active) == 0 {
		return 0
	}
	chosen := 0
	for _, candidate := range candidates {
		if !active[candidate.Tag] {
			continue
		}
		if chosen != 0 && chosen != candidate.Id {
			// Two of this account's inbounds were live this tick, so which of them
			// moved these bytes is genuinely unknown. Rule 3 stops here.
			return 0
		}
		chosen = candidate.Id
	}
	return chosen
}
