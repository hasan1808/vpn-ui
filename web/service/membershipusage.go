package service

import (
	"sort"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

// Per-inbound traffic attribution.
//
// client_traffics is unchanged and stays the ONE authoritative counter: one row per
// account, email unique panel-wide, still what RADIUS, the rbridge sink, the
// depletion sweep and every daemon read. Everything here is a BREAKDOWN written
// alongside it from the same deltas, into the membership row that already exists
// for the pair (see model.AccountInbound).
//
// The bug it fixes: an account on two inbounds had exactly one counter row, hanging
// off whichever inbound created it first, so the panel showed 100% of its usage
// under that inbound and 0 under every other one. Nothing was lost (the account
// total was always right); the split was fiction.

// membershipUsageKey is one bucket of the breakdown: this account's bytes on THIS
// inbound. The email is normalized (accountKey) for the same reason identity is
// compared that way everywhere else - the collected record carries whatever
// spelling the daemon reported.
type membershipUsageKey struct {
	inboundId int
	emailKey  string
}

// membershipUsageDelta is one tick's worth of one bucket. up/down are BILLED bytes
// and allTime is RAW, matching how the account row is written, so the breakdown and
// the total stay comparable column for column.
type membershipUsageDelta struct{ up, down, allTime int64 }

func (d *membershipUsageDelta) add(up, down, allTime int64) {
	d.up += up
	d.down += down
	d.allTime += allTime
}

// addTo records a delta under its key, creating the bucket on first use.
func addTo(deltas map[membershipUsageKey]*membershipUsageDelta, inboundId int, email string, up, down, allTime int64) {
	// Zero means "source unknown", which is not an inbound and must never be
	// attributed to one. Those bytes still reach the account total; they are simply
	// absent from the breakdown. Attributing them to a guess (the home inbound, the
	// lowest membership) is exactly the fiction this file exists to remove.
	if inboundId == 0 {
		return
	}
	key := membershipUsageKey{inboundId: inboundId, emailKey: accountKey(email)}
	if key.emailKey == "" {
		return
	}
	d := deltas[key]
	if d == nil {
		d = &membershipUsageDelta{}
		deltas[key] = d
	}
	d.add(up, down, allTime)
}

// addMembershipTraffic folds one tick's deltas into the membership rows.
//
// Best-effort, and deliberately outside the caller's error path: the authoritative
// counter has already been written by the time this runs, so failing the tick here
// would roll back real billing to protect a display figure.
//
// A delta whose membership row does not exist updates nothing and is dropped, which
// is wanted rather than a miss to fix with an insert. account_inbounds is owned by
// ApplyMemberships and SyncInboundAccounts; a row conjured here would be a
// membership the projection never made, and the next sync would delete it anyway.
func addMembershipTraffic(tx *gorm.DB, deltas map[membershipUsageKey]*membershipUsageDelta) {
	if len(deltas) == 0 || tx == nil {
		return
	}
	for key, d := range deltas {
		if d.up == 0 && d.down == 0 && d.allTime == 0 {
			continue
		}
		// COALESCE rather than a bare add: the columns arrive with DEFAULT 0 so
		// AutoMigrate fills existing rows, but a hand-edited or restored database can
		// still hold a NULL, and NULL + n is NULL in SQLite - it would silently blank
		// the membership's whole history instead of adding to it.
		err := tx.Exec(`
			UPDATE account_inbounds
			SET up = COALESCE(up, 0) + ?, down = COALESCE(down, 0) + ?, all_time = COALESCE(all_time, 0) + ?
			WHERE inbound_id = ?
			  AND account_id IN (SELECT id FROM accounts WHERE LOWER(TRIM(email)) = ?)`,
			d.up, d.down, d.allTime, key.inboundId, key.emailKey).Error
		if err != nil {
			logger.Warning("per-inbound usage: cannot attribute traffic to inbound ", key.inboundId, " for ", key.emailKey, ": ", err)
		}
	}
}

// resetMembershipUsage zeroes the breakdown for the given accounts, and is the
// mirror of a reset on client_traffics.
//
// up/down go and all_time stays, exactly as the account row behaves: a reset clears
// what counts against the quota and must not rewind the lifetime record. Called
// wherever client_traffics.up/down are zeroed, so the breakdown cannot drift into
// claiming more than the account has used.
func resetMembershipUsage(tx *gorm.DB, emails []string) {
	if tx == nil || len(emails) == 0 {
		return
	}
	keys := make([]string, 0, len(emails))
	for _, email := range emails {
		if key := accountKey(email); key != "" {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return
	}
	err := tx.Exec(`
		UPDATE account_inbounds
		SET up = 0, down = 0
		WHERE account_id IN (SELECT id FROM accounts WHERE LOWER(TRIM(email)) IN (?))`,
		keys).Error
	if err != nil {
		logger.Warning("per-inbound usage: cannot reset the breakdown: ", err)
	}
}

// countedByPanel reports whether bytes from this protocol can name the inbound they
// entered through.
//
// True for the nine pool VPN protocols (one nft counter per tunnel address, and an
// address belongs to exactly one inbound's pool) and for the two relays (telemt and
// the in-binary SSH gateway tally per account inside one inbound's daemon).
//
// False for everything Xray counts, and that is a property of the core rather than a
// gap here: the stat is named "user>>><email>>>>traffic>>>{up,down}" (xray/api.go)
// with no inbound component, so an account on vless AND trojan gets ONE number
// covering both and there is nothing to split it by.
func countedByPanel(p model.Protocol) bool { return isVpnProtocol(p) || isRelayProtocol(p) }

// mayHoldCoreTraffic reports whether an inbound can be the source of bytes that Xray
// counted per ACCOUNT without naming an inbound - the pooled remainder below.
//
// It is the same test attributeCoreRecords picks its candidates with, and shares its
// reasoning: an inbound Xray terminates itself produces a user stat, a relay's paired
// socks inbound produces one under the account's email, and a pool VPN protocol
// produces none at all because its dokodemo-door carries no user identity. Written
// once, here, so the figure a membership DISPLAYS cannot end up disagreeing with the
// set of inbounds the attribution was willing to consider.
func mayHoldCoreTraffic(p model.Protocol) bool { return !isVpnProtocol(p) }

// membershipUsageRow is one membership's share, joined to the identity it belongs to
// and to the inbound holding it.
type membershipUsageRow struct {
	InboundId int
	Email     string
	// Protocol is the inbound's, carried so the pooled remainder below can tell an
	// attributable share from one that no inbound will ever render. The join that
	// supplies it also drops any share whose inbound has been DELETED, for the same
	// reason: subtracting it would hide those bytes on every page.
	Protocol model.Protocol
	Up       int64
	Down     int64
	AllTime  int64
}

// accountUsageSplit is one account's usage, already divided.
type accountUsageSplit struct {
	// byInbound is the share of each inbound that could account for its own bytes.
	byInbound map[int]membershipUsageRow
	// pooled is what no inbound could claim: the account total minus every share
	// above. It is the Xray-native remainder, and is shown against those inbounds
	// marked Shared rather than being split between them.
	pooled xray.ClientTraffic
	// hasMemberships distinguishes "nothing has been attributed yet" from "this
	// account is not in the accounts layer at all". The second falls back to the
	// legacy rendering, so a panel whose accounts migration never ran looks exactly
	// as it did before.
	hasMemberships bool
	// email is the spelling the accounts table stores, kept because identity is
	// MATCHED case-insensitively but must be DISPLAYED as the operator typed it.
	email string
}

// attachClientStats replaces each inbound's preloaded ClientStats with the accounts
// that inbound actually SERVES, each carrying that inbound's share of the usage.
//
// Two bugs die here. ClientStats was a has-many on client_traffics.inbound_id, and
// there is exactly ONE row per account (email is unique panel-wide), so:
//
//   - the account appeared only under its home inbound and was MISSING from every
//     other inbound serving it, and
//   - the whole account's usage was rendered as that one inbound's, with the rest
//     showing nothing.
//
// The association is left on the model so Preload("ClientStats") keeps working for
// the callers that want the raw rows (sub/subService.go), but every list the panel
// renders comes through here instead.
func (s *InboundService) attachClientStats(db *gorm.DB, inbounds []*model.Inbound) error {
	if len(inbounds) == 0 {
		return nil
	}

	// The whole table, not a WHERE IN over the emails found below. One scan beats
	// thousands of bound parameters (SQLite has a hard limit on those), it is what
	// the Clients page already does for the same data (see ListAccounts), and these
	// callers are loading every inbound anyway.
	var traffics []xray.ClientTraffic
	if err := db.Find(&traffics).Error; err != nil {
		return err
	}
	byEmail := make(map[string]*xray.ClientTraffic, len(traffics))
	for i := range traffics {
		byEmail[accountKey(traffics[i].Email)] = &traffics[i]
	}

	// The inbound is joined as well as the account, so each share arrives knowing
	// which protocol holds it. An INNER join on both sides is the point: a share
	// whose inbound is gone is not a membership any more, and counting it would go
	// on subtracting those bytes from the remainder below with no row left to render
	// them under.
	var shares []membershipUsageRow
	if err := db.Table("account_inbounds").
		Select("account_inbounds.inbound_id AS inbound_id, accounts.email AS email, " +
			"inbounds.protocol AS protocol, " +
			"COALESCE(account_inbounds.up, 0) AS up, COALESCE(account_inbounds.down, 0) AS down, " +
			"COALESCE(account_inbounds.all_time, 0) AS all_time").
		Joins("JOIN accounts ON accounts.id = account_inbounds.account_id").
		Joins("JOIN inbounds ON inbounds.id = account_inbounds.inbound_id").
		Scan(&shares).Error; err != nil {
		return err
	}

	splits := make(map[string]*accountUsageSplit, len(byEmail))
	for _, share := range shares {
		key := accountKey(share.Email)
		if key == "" {
			continue
		}
		split := splits[key]
		if split == nil {
			split = &accountUsageSplit{byInbound: map[int]membershipUsageRow{}}
			splits[key] = split
		}
		split.hasMemberships = true
		split.email = share.Email
		split.byInbound[share.InboundId] = share
	}

	// What is left after every inbound took its share. Floored at zero: the two sides
	// are written by different statements in the same tick and a reset clears them
	// independently, so a momentary negative is possible and reads far worse than a
	// zero.
	//
	// EVERY share is subtracted, including those on Xray-native inbounds, because
	// those are now real: attributeCoreRecords resolves the core's inbound-less
	// records to one inbound whenever only one of the account's could have produced
	// them, and clientStatsFor below renders that share. A share left out of this sum
	// would be displayed by its own inbound AND still be sitting in the remainder
	// every other Xray inbound shows, so the account's usage would appear twice.
	//
	// The historical hazard this replaces was the mirror image: back when an
	// Xray-native inbound rendered only the remainder, a share parked on one was
	// subtracted here and displayed nowhere at all, so the Clients page read 0 used
	// against every inbound of an account that had moved gigabytes. That is what
	// MigrationMembershipUsage's first backfill did (it filed each account's whole
	// history under client_traffics.inbound_id, which on most panels is a vless or
	// vmess inbound), and repairMembershipUsage clears those rows.
	for key, split := range splits {
		total := byEmail[key]
		if total == nil {
			continue
		}
		var up, down, allTime int64
		for _, share := range split.byInbound {
			up += share.Up
			down += share.Down
			allTime += share.AllTime
		}
		split.pooled = xray.ClientTraffic{
			Up:      max64(total.Up-up, 0),
			Down:    max64(total.Down-down, 0),
			AllTime: max64(total.AllTime-allTime, 0),
		}
	}

	for _, inbound := range inbounds {
		inbound.ClientStats = s.clientStatsFor(inbound, byEmail, splits)
	}
	return nil
}

// clientStatsFor builds one inbound's rendered rows.
func (s *InboundService) clientStatsFor(
	inbound *model.Inbound,
	byEmail map[string]*xray.ClientTraffic,
	splits map[string]*accountUsageSplit,
) []xray.ClientTraffic {
	// Whether this inbound can be holding some of what the core could not place. Only
	// such an inbound shows the pooled remainder on top of its own share.
	pooledHere := mayHoldCoreTraffic(inbound.Protocol)

	stats := make([]xray.ClientTraffic, 0, 8)
	seen := map[string]bool{}
	add := func(email string) {
		key := accountKey(email)
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		total := byEmail[key]
		if total == nil {
			// No quota row means no account to show. Not an error: a settings entry
			// can briefly exist without one, and inventing a row here would put a
			// client on the page with a quota and an expiry nobody set.
			return
		}
		// Up/Down/AllTime are left exactly as client_traffics holds them: the
		// account's own totals, which is what the quota bars and the depletion
		// checks must keep comparing against. Only the Inbound* fields below are
		// this inbound's slice.
		row := *total
		// The inbound this row is being RENDERED under, not the account's home
		// inbound. The page passes it straight back as the :id of
		// /resetClientTraffic and /:id/delClient, and the home inbound is frequently
		// one the caller has no grant on, which failed the ownership check on an
		// inbound they were looking at.
		row.InboundId = inbound.Id

		split := splits[key]
		switch {
		case split == nil || !split.hasMemberships:
			// Not in the accounts layer, so there is nothing to attribute with.
			// Render what the has-many used to: the whole account under its home
			// inbound, nothing anywhere else. This is the panel whose accounts
			// migration has not run (or failed), and it must look untouched.
			row.InboundId = total.InboundId
			if total.InboundId == inbound.Id {
				row.InboundUp, row.InboundDown, row.InboundAllTime = total.Up, total.Down, total.AllTime
			}
		default:
			// This inbound's own share: the ticks whose source was known, which is
			// every tick for a protocol the panel meters itself and the resolvable
			// ones for an inbound Xray terminates.
			share := split.byInbound[inbound.Id]
			row.InboundUp, row.InboundDown, row.InboundAllTime = share.Up, share.Down, share.AllTime
			// Plus what the core could not place, if this inbound is one of the
			// inbounds it could have come through. Added rather than substituted, so
			// an inbound with a resolved share does not lose it, and flagged so the
			// page can say the surplus is shared with the account's other Xray
			// inbounds instead of implying this one moved all of it.
			//
			// A zero here would read as "this customer has never used it", which is
			// what the pooling exists to avoid saying.
			if pooledHere && split.pooled.Up+split.pooled.Down+split.pooled.AllTime > 0 {
				row.InboundUp += split.pooled.Up
				row.InboundDown += split.pooled.Down
				row.InboundAllTime += split.pooled.AllTime
				row.Shared = true
			}
		}
		stats = append(stats, row)
	}

	// settings.clients first and in its own order, because that is the order the
	// page lists clients in, then the memberships that have not been spliced into
	// settings yet. Mirrors inboundAccountEmails, inlined because that one queries
	// per inbound and this runs over every inbound in the panel.
	if clients, ok := parseSettingsClients(inbound.Settings); ok {
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			add(email)
		}
	}
	// Sorted, so two identical panels render the same list. Map order is random and
	// these rows land at the end of a table an operator reads top to bottom.
	extra := make([]string, 0, 4)
	for key, split := range splits {
		if _, serves := split.byInbound[inbound.Id]; !serves || seen[key] {
			continue
		}
		extra = append(extra, split.email)
	}
	sort.Strings(extra)
	for _, email := range extra {
		add(email)
	}
	return stats
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// -----------------------------------------------------------------------------
// Backfill
// -----------------------------------------------------------------------------

// membershipUsageMigratedKey is the setting that records the backfill has run.
const membershipUsageMigratedKey = "membershipUsageBackfilledAt"

// membershipUsageRepairedKey guards the one-shot repair of the shares the FIRST
// backfill parked on inbounds that cannot render them. It is a second key rather
// than a bump of the one above because the two do opposite things and a panel can
// need either, both, or neither: a fresh install seeds and has nothing to repair, a
// panel upgraded from the release that shipped the bug has already seeded and needs
// only the repair.
const membershipUsageRepairedKey = "membershipUsageRepairedAt"

// MigrationMembershipUsage seeds the per-inbound breakdown from the usage that
// exists today.
//
// There is no historical split to recover: until this release every byte was
// counted against one account-wide row, so the honest backfill is to put the whole
// of it on the membership that row already named (client_traffics.inbound_id, the
// account's home inbound) and let new ticks divide correctly from here. It FREEZES
// today's wrong attribution as the historical bucket rather than inventing a better
// looking one; dividing evenly across memberships would be making data up.
//
// Operators need telling, because an account that has been split across two
// inbounds all along will keep showing all its history under one of them.
//
// Runs on every start (not from MigrateDB, which only the `migrate` subcommand and
// the DB-import path reach) and guards itself with a setting, so a panel that has
// been running the split for weeks is never re-flattened.
func (s *AccountService) MigrationMembershipUsage() {
	db := database.GetDB()
	if db == nil {
		return
	}

	s.repairMembershipUsage(db)

	var settingService SettingService
	// getSetting rather than getString: getString demands the key be in
	// defaultValueMap and errors otherwise, so the ordinary "never run" case would
	// take an error path on every start.
	if setting, err := settingService.getSetting(membershipUsageMigratedKey); err == nil && setting != nil && setting.Value != "" {
		return
	}

	seeded := 0
	err := db.Transaction(func(tx *gorm.DB) error {
		var memberships []model.AccountInbound
		if err := tx.Order("inbound_id ASC").Find(&memberships).Error; err != nil {
			return err
		}
		if len(memberships) == 0 {
			// Nothing to seed. Still flagged as done: a panel with no accounts layer
			// yet gets its memberships created with zeroed counters by
			// ApplyMemberships, which is already correct.
			return nil
		}
		byAccount := map[int][]int{}
		for _, m := range memberships {
			byAccount[m.AccountId] = append(byAccount[m.AccountId], m.InboundId)
		}

		var accounts []model.Account
		if err := tx.Select("id", "email").Find(&accounts).Error; err != nil {
			return err
		}
		idByEmail := make(map[string]int, len(accounts))
		for _, account := range accounts {
			idByEmail[accountKey(account.Email)] = account.Id
		}

		// Which inbounds can hold a share: still there, and able to render one.
		//
		// Existence, because an account whose home inbound was deleted is common
		// (nothing prunes client_traffics.inbound_id when its inbound goes) and
		// seeding a membership that is not there would drop the history.
		//
		// And attributable, because an Xray-native inbound does not display its own
		// share at all: it displays the account's unattributed REMAINDER, which is the
		// total minus every share. Seeding one therefore subtracts the history from
		// the only figure that would have shown it, and the account reads zero used on
		// every inbound it is on. See the remainder loop in attachClientStats.
		var liveRows []struct {
			Id       int
			Protocol model.Protocol
		}
		if err := tx.Model(&model.Inbound{}).Select("id", "protocol").Scan(&liveRows).Error; err != nil {
			return err
		}
		live := make(map[int]bool, len(liveRows))
		attributable := make(map[int]bool, len(liveRows))
		for _, row := range liveRows {
			live[row.Id] = true
			if countedByPanel(row.Protocol) {
				attributable[row.Id] = true
			}
		}

		var traffics []xray.ClientTraffic
		if err := tx.Find(&traffics).Error; err != nil {
			return err
		}

		for _, traffic := range traffics {
			if traffic.Up == 0 && traffic.Down == 0 && traffic.AllTime == 0 {
				continue
			}
			accountId, ok := idByEmail[accountKey(traffic.Email)]
			if !ok {
				continue
			}
			inboundIds := byAccount[accountId]
			if len(inboundIds) == 0 {
				continue
			}
			sort.Ints(inboundIds)

			// The home inbound when it is really a membership and really still there.
			// If it is one that cannot hold a share, the history stays UNATTRIBUTED:
			// the remainder is exactly where a byte with no known source belongs, and
			// moving it to some other inbound of the account's would be inventing an
			// attribution the panel was never told.
			//
			// The fallback to the lowest live membership is only for a home inbound
			// that is not there at all, where nothing is known either way and one
			// deterministic guess beats losing the history. Ascending order makes it
			// deterministic rather than "whichever the database returned first", and it
			// still has to be one that can render what it is given.
			target := 0
			homeIsMembership := false
			for _, id := range inboundIds {
				if id == traffic.InboundId && live[id] {
					homeIsMembership = true
					if attributable[id] {
						target = id
					}
					break
				}
			}
			if target == 0 && homeIsMembership {
				continue
			}
			if target == 0 {
				for _, id := range inboundIds {
					if attributable[id] {
						target = id
						break
					}
				}
			}
			if target == 0 {
				continue
			}

			if err := tx.Model(&model.AccountInbound{}).
				Where("account_id = ? AND inbound_id = ?", accountId, target).
				Updates(map[string]any{
					"up":       traffic.Up,
					"down":     traffic.Down,
					"all_time": traffic.AllTime,
				}).Error; err != nil {
				return err
			}
			seeded++
		}
		return nil
	})
	if err != nil {
		// Rolled back, the flag stays unset, and the next start retries. The panel is
		// unaffected either way: the breakdown is a display figure and every
		// enforcement path still reads client_traffics.
		logger.Warning("MigrationMembershipUsage - seeding the per-inbound breakdown failed, will retry on the next start: ", err)
		return
	}

	if err := settingService.setString(membershipUsageMigratedKey, time.Now().Format(time.RFC3339)); err != nil {
		logger.Warning("MigrationMembershipUsage - could not set the migrated flag: ", err)
		return
	}
	if seeded > 0 {
		logger.Infof("MigrationMembershipUsage - seeded the per-inbound breakdown for %d account(s); their existing usage is filed under the inbound they were created on", seeded)
	}
}

// repairMembershipUsage clears the shares the first backfill filed against inbounds
// that never display one.
//
// The release that introduced the breakdown seeded every account's whole history
// under client_traffics.inbound_id without asking what protocol that inbound speaks.
// An Xray-native inbound renders the account's unattributed REMAINDER, not its own
// share, so a share sitting on one is subtracted from the remainder and shown by
// nothing: the Clients page reported 0 used against every single inbound of an
// account that had moved gigabytes. attachClientStats now ignores such a share when
// it computes the remainder, which fixes the display on its own; this puts the table
// back in agreement with it so the two cannot be read against each other and
// disagree.
//
// Nothing is lost by zeroing them. client_traffics is untouched and remains the
// authoritative total, and these bytes go straight back into the remainder, which is
// where a byte Xray could not place belongs.
//
// Deliberately NOT restricted to rows the backfill wrote: the live path cannot
// produce one (an Xray record carries no inbound id, and addTo drops the ones that
// name none), so every such row is either the backfill's or corruption, and both
// want clearing.
func (s *AccountService) repairMembershipUsage(db *gorm.DB) {
	var settingService SettingService
	if setting, err := settingService.getSetting(membershipUsageRepairedKey); err == nil && setting != nil && setting.Value != "" {
		return
	}

	var stray []int
	var inbounds []model.Inbound
	if err := db.Model(&model.Inbound{}).Select("id", "protocol").Find(&inbounds).Error; err != nil {
		logger.Warning("MigrationMembershipUsage - cannot list inbounds to repair the breakdown, will retry on the next start: ", err)
		return
	}
	for i := range inbounds {
		if !countedByPanel(inbounds[i].Protocol) {
			stray = append(stray, inbounds[i].Id)
		}
	}

	cleared := int64(0)
	if len(stray) > 0 {
		res := db.Exec(`
			UPDATE account_inbounds SET up = 0, down = 0, all_time = 0
			WHERE inbound_id IN (?)
			  AND (COALESCE(up, 0) <> 0 OR COALESCE(down, 0) <> 0 OR COALESCE(all_time, 0) <> 0)`,
			stray)
		if res.Error != nil {
			logger.Warning("MigrationMembershipUsage - cannot clear the misfiled breakdown, will retry on the next start: ", res.Error)
			return
		}
		cleared = res.RowsAffected
	}

	if err := settingService.setString(membershipUsageRepairedKey, time.Now().Format(time.RFC3339)); err != nil {
		logger.Warning("MigrationMembershipUsage - could not set the repaired flag: ", err)
		return
	}
	if cleared > 0 {
		logger.Infof("MigrationMembershipUsage - moved %d misfiled per-inbound total(s) back into the account's unattributed usage; those inbounds are counted by Xray, which does not say which inbound a byte came through", cleared)
	}
}
