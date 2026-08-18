package service

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

// orphanCleanupMigratedKey is the setting that records this pass has run.
const orphanCleanupMigratedKey = "orphanRecordsCleanedAt"

// orphanReportLogLimit caps the per-run detail, like accountsConflictLogLimit. A
// panel with hundreds of collisions has one systemic cause, and the log is not the
// place to enumerate it.
const orphanReportLogLimit = 50

// MigrationCleanupOrphans clears the records a failed delete left behind.
//
// Every install predating the delete fixes carries them: the panel refused to
// remove the last client of an inbound, refused the second membership of an account
// whose single counter row the first membership had already taken, and matched
// emails byte-exactly where the rest of the panel matches case-insensitively. Each
// of those aborts a delete PART WAY THROUGH, so what is left is not one consistent
// state but three: a membership for an inbound that no longer exists, an account
// with no membership at all, and a counter row no settings entry claims. All three
// hold an email against a re-create, which the operator sees as the panel refusing
// a "Duplicate email" for a customer they deleted.
//
// It removes only records nothing can reach:
//
//  1. account_inbounds rows naming an inbound that is gone, then accounts left with
//     no membership at all.
//  2. client_traffics rows no inbound's settings claims (removeOrphanedTraffics).
//
// AND IT REPORTS, WITHOUT DELETING, the one class that looks identical from a
// distance: two settings entries that resolve to the SAME account identity. Those
// are live paying customers, not debris, and auto-deleting one is the single thing
// this pass must never do - it would take a working account off an inbound with no
// trace but a log line. They are logged for an operator to settle by hand.
//
// Runs on every start rather than from MigrateDB (which only the `migrate`
// subcommand and the DB-import path reach, so a panel that is simply upgraded would
// never call it) and guards itself with a setting so it cannot re-run.
func (s *InboundService) MigrationCleanupOrphans() {
	db := database.GetDB()
	if db == nil {
		return
	}

	var settingService SettingService
	// getSetting rather than getString: getString demands the key be in
	// defaultValueMap and errors otherwise, so the ordinary "never run" case would
	// take an error path on every start.
	if setting, err := settingService.getSetting(orphanCleanupMigratedKey); err == nil && setting != nil && setting.Value != "" {
		return
	}

	// Reported before anything is deleted, so what the operator reads describes the
	// state that was actually found rather than what survived the pass.
	reportDuplicateIdentities(db)

	staleMemberships, prunedAccounts := 0, 0
	err := db.Transaction(func(tx *gorm.DB) error {
		var referenced []int
		if err := tx.Model(&model.AccountInbound{}).Distinct().Pluck("inbound_id", &referenced).Error; err != nil {
			return err
		}
		var liveIds []int
		if err := tx.Model(&model.Inbound{}).Pluck("id", &liveIds).Error; err != nil {
			return err
		}
		live := make(map[int]bool, len(liveIds))
		for _, id := range liveIds {
			live[id] = true
		}
		var stale []int
		for _, id := range referenced {
			if !live[id] {
				stale = append(stale, id)
			}
		}
		if len(stale) > 0 {
			result := tx.Where("inbound_id IN ?", stale).Delete(&model.AccountInbound{})
			if result.Error != nil {
				return result.Error
			}
			staleMemberships = int(result.RowsAffected)
		}

		var accountCount, membershipCount int64
		if err := tx.Model(&model.Account{}).Count(&accountCount).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.AccountInbound{}).Count(&membershipCount).Error; err != nil {
			return err
		}
		// The prune is skipped when there are accounts but not a single membership
		// left. Every account then reads as an orphan and the pass would delete the
		// lot, which is right where the prune is normally called (straight after
		// removing the memberships that emptied them) and wrong here: on a panel whose
		// mirror never got its memberships written, it would take out every account row
		// and the per-account credentials that hang off them. Nothing can reach those
		// accounts either way, so leaving them costs nothing and the next reconcile
		// fixes them.
		if accountCount > 0 && membershipCount == 0 {
			logger.Warningf("MigrationCleanupOrphans - %d account(s) and no memberships at all; the prune is skipped rather than emptying the accounts table", accountCount)
			return nil
		}

		// Every account is a candidate here, which is the one place that is still the
		// right question to ask: this is a ONE-SHOT repair of a database written before
		// an account could deliberately hold no membership (the setting key above is
		// what stops it running twice), so an empty account in it is a leftover of the
		// bug this pass exists to clean up and not an operator's decision.
		var allAccounts []int
		if err := tx.Session(&gorm.Session{NewDB: true}).
			Model(&model.Account{}).Pluck("id", &allAccounts).Error; err != nil {
			return err
		}
		var accountService AccountService
		if err := accountService.pruneOrphanAccounts(tx, allAccounts); err != nil {
			return err
		}
		var after int64
		if err := tx.Model(&model.Account{}).Count(&after).Error; err != nil {
			return err
		}
		prunedAccounts = int(accountCount - after)
		return nil
	})
	if err != nil {
		// Rolled back, the flag stays unset, and the next start retries. Nothing the
		// panel serves depends on this having run: the records it removes are exactly
		// the ones nothing can reach.
		logger.Warning("MigrationCleanupOrphans - the accounts cleanup failed, will retry on the next start: ", err)
		return
	}

	// Outside the transaction above on purpose: it is a single self-contained DELETE
	// against a different table, and a failure in it must not roll back the account
	// cleanup that already succeeded.
	orphanTraffics := int64(0)
	if before, cerr := countClientTraffics(db); cerr == nil {
		if terr := removeOrphanedTraffics(db); terr != nil {
			logger.Warning("MigrationCleanupOrphans - removing orphaned traffic rows: ", terr)
		} else if after, aerr := countClientTraffics(db); aerr == nil {
			orphanTraffics = before - after
		}
	}

	if err := settingService.setString(orphanCleanupMigratedKey, time.Now().Format(time.RFC3339)); err != nil {
		logger.Warning("MigrationCleanupOrphans - could not set the migrated flag: ", err)
		return
	}
	if staleMemberships > 0 || prunedAccounts > 0 || orphanTraffics > 0 {
		logger.Infof("MigrationCleanupOrphans - removed %d membership(s) of deleted inbounds, %d account(s) left serving nothing and %d unclaimed traffic row(s); the emails they held are free to re-create",
			staleMemberships, prunedAccounts, orphanTraffics)
	}
}

// countClientTraffics is only here so the pass can report how many rows the GC
// actually took: removeOrphanedTraffics is one raw DELETE and gorm reports no row
// count for it.
func countClientTraffics(db *gorm.DB) (int64, error) {
	var n int64
	err := db.Model(&xray.ClientTraffic{}).Count(&n).Error
	return n, err
}

// reportDuplicateIdentities logs the settings entries that resolve to one account
// identity, and deletes NOTHING.
//
// Two shapes, both of which the delete and duplicate-check fixes make visible for
// the first time:
//
//   - two entries in ONE inbound sharing an accountKey. The inbound serves the same
//     customer twice; whichever the core indexes second is unreachable, and the
//     account's traffic is booked once.
//   - one accountKey spelled differently across inbounds ("Bob" here, "bob" there).
//     The app treats those as one account and the client_traffics unique index,
//     which is BINARY, treats them as two. Whichever way it is settled, it moves a
//     paying customer's quota.
//
// Reported rather than repaired because either repair is destructive and neither is
// decidable from here: merging picks one spelling and one quota, deleting picks a
// customer to cut off. An operator can see which is which; this pass cannot.
func reportDuplicateIdentities(db *gorm.DB) {
	var inbounds []*model.Inbound
	if err := db.Model(&model.Inbound{}).
		Select("id", "remark", "settings").
		Order("id ASC").Find(&inbounds).Error; err != nil {
		logger.Warning("MigrationCleanupOrphans - cannot scan the settings for duplicate identities: ", err)
		return
	}

	type spread struct {
		spellings map[string]bool
		inbounds  map[int]bool
	}
	global := map[string]*spread{}
	var reports []string

	for _, inbound := range inbounds {
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		seen := map[string]string{}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			key := accountKey(email)
			if key == "" {
				continue
			}
			if first, dup := seen[key]; dup {
				reports = append(reports, fmt.Sprintf("inbound %d (%q) serves %q twice, as %q and %q",
					inbound.Id, inbound.Remark, key, first, email))
			} else {
				seen[key] = email
			}
			if global[key] == nil {
				global[key] = &spread{spellings: map[string]bool{}, inbounds: map[int]bool{}}
			}
			global[key].spellings[email] = true
			global[key].inbounds[inbound.Id] = true
		}
	}

	keys := make([]string, 0, len(global))
	for key := range global {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := global[key]
		if len(entry.spellings) < 2 {
			continue
		}
		spellings := make([]string, 0, len(entry.spellings))
		for spelling := range entry.spellings {
			spellings = append(spellings, fmt.Sprintf("%q", spelling))
		}
		sort.Strings(spellings)
		ids := make([]int, 0, len(entry.inbounds))
		for id := range entry.inbounds {
			ids = append(ids, id)
		}
		sort.Ints(ids)
		reports = append(reports, fmt.Sprintf("%q is spelled %s across inbound(s) %s",
			key, strings.Join(spellings, ", "), joinInts(ids)))
	}

	if len(reports) == 0 {
		return
	}
	logger.Warningf("MigrationCleanupOrphans - %d client entry conflict(s) found. NOTHING was deleted: these are live accounts and settling them moves a paying customer's quota, so they are left exactly as they are for an operator to decide.", len(reports))
	for i, report := range reports {
		if i >= orphanReportLogLimit {
			logger.Warningf("MigrationCleanupOrphans - %d further conflict(s) not listed", len(reports)-orphanReportLogLimit)
			break
		}
		logger.Warning("MigrationCleanupOrphans - ", report)
	}
}

func joinInts(ids []int) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprint(id))
	}
	return strings.Join(parts, ", ")
}
