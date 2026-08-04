package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"

	"gorm.io/gorm"
)

// MigrationAccounts backfills the accounts layer from the settings.clients arrays
// that are the panel's only client storage before it exists.
//
// THE ONE PROPERTY EVERYTHING ELSE RESTS ON:
//
//	This pass is ADDITIVE ONLY. It never writes to inbounds, client_traffics,
//	reseller_clients or inbound_client_ips. It only INSERTs into accounts and
//	account_inbounds.
//
// That single constraint buys, for free:
//
//   - A failure at any point leaves the database byte-identical to before it ran.
//   - No user-visible half-migrated state: settings.clients stays the truth the
//     whole time, and every daemon, generator and allocator keeps reading it.
//   - An old binary rolled back onto a migrated database ignores both new tables
//     and behaves exactly as it did before.
//   - The pass can be aborted, retried or skipped with no consequence.
//
// Any change that makes this rewrite settings.clients forfeits all four. Do not.
const (
	accountsMigratedKey = "accountsMigratedAt"
	accountsReportKey   = "accountsMigrationReport"
	accountsBackupKey   = "accountsPreMigrationBackup"
)

// AccountMergeConflict records a divergence found while folding several client
// entries that share one email into one account. Surfacing it beats silently
// picking a winner.
type AccountMergeConflict struct {
	Email     string `json:"email"`
	Field     string `json:"field"`
	InboundId int    `json:"inboundId"`
	Old       string `json:"old"`
	New       string `json:"new"`
	Kept      string `json:"kept"`
}

// conflictPair identifies the one client entry a conflict was found on.
//
// It exists so the round-trip verification can tell a genuine projection bug
// apart from a KNOWN, REPORTED divergence. When one email appears on two
// inbounds with different quotas, the first wins and the second's entry no
// longer matches the account by construction. That is the documented outcome,
// not a failure, so those pairs are excluded from check 3 rather than being
// allowed to roll the whole migration back.
type conflictPair struct {
	emailKey  string
	inboundId int
}

// AccountsMigrationReport is the advisory output of one pass, stored in settings
// and surfaced in the panel. Advice, never authorization.
type AccountsMigrationReport struct {
	RanAt              int64                  `json:"ranAt"`
	AccountsCreated    int                    `json:"accountsCreated"`
	MembershipsCreated int                    `json:"membershipsCreated"`
	InboundsSkipped    []int                  `json:"inboundsSkipped"`
	ClientsSkipped     int                    `json:"clientsSkipped"`
	InvalidIdentity    []string               `json:"invalidIdentity"`
	Conflicts          []AccountMergeConflict `json:"conflicts"`
	BackupPath         string                 `json:"backupPath"`
}

// MigrationAccounts runs the backfill. It is called on EVERY start (not from
// MigrateDB, which only the `migrate` subcommand and the DB-import path reach),
// so an inbound added by an older binary or a DB restored from backup is picked
// up. It is idempotent, non-fatal, and cheap to re-check.
// How many merge conflicts are listed individually before the log falls back to a
// count. A panel with thousands of colliding entries should not have its log
// buried, and the pattern is clear long before that.
const accountsConflictLogLimit = 50

func (s *AccountService) MigrationAccounts() {
	db := database.GetDB()
	if db == nil {
		return
	}

	needed, totalEntries, err := s.migrationNeeded(db)
	if err != nil {
		logger.Warning("MigrationAccounts - could not determine whether a pass is needed: ", err)
		return
	}
	if !needed {
		return
	}

	// Pre-flight backup, once, before the FIRST pass only. An upgrade without a
	// good backup is not worth it: if this fails we skip the migration entirely
	// and the panel starts normally on the legacy path.
	backupPath, err := s.ensurePreMigrationBackup()
	if err != nil {
		logger.Error("MigrationAccounts - pre-flight backup failed, SKIPPING the migration; the panel continues on the legacy client model: ", err)
		return
	}

	report := AccountsMigrationReport{RanAt: time.Now().UnixMilli(), BackupPath: backupPath}

	txErr := db.Transaction(func(tx *gorm.DB) error {
		return s.runAccountsPass(tx, &report, totalEntries)
	})
	if txErr != nil {
		// Rolled back. Nothing was written, the flag stays unset, and the panel
		// runs on the legacy path exactly as before.
		logger.Error("MigrationAccounts - pass FAILED and was rolled back; the panel continues on the legacy client model: ", txErr)
		return
	}

	var settingService SettingService
	if blob, err := json.Marshal(report); err == nil {
		if err := settingService.setString(accountsReportKey, string(blob)); err != nil {
			logger.Warning("MigrationAccounts - could not store the report: ", err)
		}
	}
	if err := settingService.setString(accountsMigratedKey, fmt.Sprint(report.RanAt)); err != nil {
		logger.Warning("MigrationAccounts - could not set the migrated flag: ", err)
		return
	}

	logger.Infof("MigrationAccounts - %d accounts and %d memberships backfilled (%d clients skipped, %d conflicts, %d inbounds skipped)",
		report.AccountsCreated, report.MembershipsCreated, report.ClientsSkipped,
		len(report.Conflicts), len(report.InboundsSkipped))

	// Each conflict, not just the count. A conflict means two settings entries
	// shared one email and disagreed, so one side's value was dropped: first-seen
	// wins (inbounds are walked in ascending id). For a credential field that is
	// not cosmetic, the losing side's subscribers keep a credential the projection
	// will overwrite the moment anything writes with an inboundIds set.
	//
	// The full detail is also stored under accountsMigrationReport, but nothing
	// reads it back, so the log is the only place an operator can see this at all.
	for i, c := range report.Conflicts {
		if i >= accountsConflictLogLimit {
			logger.Warningf("MigrationAccounts - %d further conflicts not listed; see the stored report",
				len(report.Conflicts)-accountsConflictLogLimit)
			break
		}
		logger.Warningf("MigrationAccounts - %q: inbound %d wanted %s=%q, kept %q",
			c.Email, c.InboundId, c.Field, c.New, c.Kept)
	}
}

// migrationNeeded is the cheap re-run guard. It answers "do the accounts tables
// already describe every client entry", which is the only question that matters:
// the flag alone is not enough, because an inbound added afterwards by an older
// binary would never be picked up.
func (s *AccountService) migrationNeeded(db *gorm.DB) (bool, int, error) {
	var inbounds []*model.Inbound
	if err := db.Model(&model.Inbound{}).Select("id", "protocol", "settings").Find(&inbounds).Error; err != nil {
		return false, 0, err
	}

	emails := map[string]struct{}{}
	entries := 0
	for _, inbound := range inbounds {
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		for _, entry := range clients {
			email, _ := entry["email"].(string)
			if accountKey(email) == "" {
				continue
			}
			emails[accountKey(email)] = struct{}{}
			entries++
		}
	}

	var accountCount, membershipCount int64
	if err := db.Model(&model.Account{}).Count(&accountCount).Error; err != nil {
		return false, 0, err
	}
	if err := db.Model(&model.AccountInbound{}).Count(&membershipCount).Error; err != nil {
		return false, 0, err
	}

	if int(accountCount) == len(emails) && int(membershipCount) == entries {
		return false, entries, nil
	}
	return true, entries, nil
}

// parseSettingsClients pulls the clients array out of an inbound's settings.
// Returns ok=false for settings that cannot be parsed, which the caller must
// treat as "skip this inbound", never as "this inbound has no clients".
func parseSettingsClients(settings string) ([]map[string]any, bool) {
	var root map[string]any
	if err := json.Unmarshal([]byte(settings), &root); err != nil || root == nil {
		return nil, false
	}
	list, ok := root["clients"].([]any)
	if !ok {
		// A protocol whose settings legitimately carry no clients array.
		return nil, true
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, entry)
	}
	return out, true
}

// runAccountsPass is the migration proper, inside the caller's transaction.
//
// Inbounds are walked in ASCENDING ID ORDER so that "first wins" is deterministic
// rather than whatever the query planner happens to return.
func (s *AccountService) runAccountsPass(tx *gorm.DB, report *AccountsMigrationReport, totalEntries int) error {
	var inbounds []*model.Inbound
	if err := tx.Model(&model.Inbound{}).Order("id ASC").Find(&inbounds).Error; err != nil {
		return err
	}

	// Existing rows, so a re-run after a partially-populated table converges
	// instead of colliding on the unique index.
	byKey := map[string]*model.Account{}
	var existing []model.Account
	if err := tx.Find(&existing).Error; err != nil {
		return err
	}
	for i := range existing {
		byKey[accountKey(existing[i].Email)] = &existing[i]
	}

	seenMembership := map[[2]int]bool{}
	var existingMemberships []model.AccountInbound
	if err := tx.Find(&existingMemberships).Error; err != nil {
		return err
	}
	for _, m := range existingMemberships {
		seenMembership[[2]int{m.AccountId, m.InboundId}] = true
	}

	conflicted := map[conflictPair]bool{}

	for _, inbound := range inbounds {
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			// A hand-edited or corrupt settings blob. Skip THIS inbound and keep
			// going: it stays legacy-only, which is safe, and the rest migrate.
			report.InboundsSkipped = append(report.InboundsSkipped, inbound.Id)
			logger.Warningf("MigrationAccounts - inbound %d has unparseable settings, left on the legacy path", inbound.Id)
			continue
		}

		for listIndex, entry := range clients {
			email, _ := entry["email"].(string)
			key := accountKey(email)
			if key == "" {
				// No email, no account identity. Allowed today, so counted rather
				// than treated as an error.
				report.ClientsSkipped++
				continue
			}

			account, exists := byKey[key]
			if !exists {
				account = newAccountFromEntry(entry)
				if err := tx.Create(account).Error; err != nil {
					return fmt.Errorf("creating account %q: %w", email, err)
				}
				byKey[key] = account
				report.AccountsCreated++
			} else {
				mergeAccountFields(account, entry, inbound.Id, report, conflicted)
			}
			// Credentials are per FIELD, so an account on vless and l2tp fills two
			// different columns and there is no conflict at all. Only two entries
			// claiming the SAME field differently are a real divergence.
			if changed := extractAccountCredential(account, entry, inbound.Protocol, inbound.Id, report, conflicted); changed {
				if err := tx.Save(account).Error; err != nil {
					return fmt.Errorf("updating account %q: %w", email, err)
				}
			}

			if seenMembership[[2]int{account.Id, inbound.Id}] {
				continue
			}
			membership := model.AccountInbound{
				AccountId: account.Id,
				InboundId: inbound.Id,
			}
			if slotPoolProtocol(inbound.Protocol) {
				// slotOr's rule: a row written before slots existed effectively
				// holds its LIST INDEX. Stamping that is what keeps its tunnel
				// address exactly where it already is.
				slot := entrySlotOr(entry, listIndex)
				membership.Slot = &slot
			}
			if inbound.Protocol == model.VLESS {
				flow, _ := entry["flow"].(string)
				membership.Flow = flow
			}
			// The entry VERBATIM, so the projection can overlay onto it and never
			// drop a field this code does not model (wg-c/awg device keypairs,
			// GRE pinned peers, anything added later).
			if blob, err := json.Marshal(entry); err == nil {
				membership.Extra = string(blob)
			}
			if err := tx.Create(&membership).Error; err != nil {
				return fmt.Errorf("creating membership %q on inbound %d: %w", email, inbound.Id, err)
			}
			seenMembership[[2]int{account.Id, inbound.Id}] = true
			report.MembershipsCreated++
		}
	}

	return s.verifyAccountsPass(tx, report, totalEntries, conflicted)
}

// verifyAccountsPass is the whole safety argument, as three assertions. A failure
// rolls the entire pass back and leaves the flag unset: half-enabling is not an
// option, and the legacy path is fully functional without the accounts layer.
func (s *AccountService) verifyAccountsPass(tx *gorm.DB, report *AccountsMigrationReport, totalEntries int, conflicted map[conflictPair]bool) error {
	var inbounds []*model.Inbound
	if err := tx.Model(&model.Inbound{}).Order("id ASC").Find(&inbounds).Error; err != nil {
		return err
	}
	skipped := map[int]bool{}
	for _, id := range report.InboundsSkipped {
		skipped[id] = true
	}

	var accounts []model.Account
	if err := tx.Find(&accounts).Error; err != nil {
		return err
	}
	accountById := map[int]*model.Account{}
	for i := range accounts {
		accountById[accounts[i].Id] = &accounts[i]
	}

	var memberships []model.AccountInbound
	if err := tx.Find(&memberships).Error; err != nil {
		return err
	}
	byPair := map[[2]int]*model.AccountInbound{}
	membershipsPerAccount := map[int]int{}
	for i := range memberships {
		m := &memberships[i]
		byPair[[2]int{m.AccountId, m.InboundId}] = m
		membershipsPerAccount[m.AccountId]++
	}

	// Check 2: every account has at least one membership (no orphans).
	for _, account := range accounts {
		if membershipsPerAccount[account.Id] == 0 {
			return fmt.Errorf("verification failed: account %q (id %d) has no membership", account.Email, account.Id)
		}
	}

	accountByKey := map[string]*model.Account{}
	for i := range accounts {
		accountByKey[accountKey(accounts[i].Email)] = &accounts[i]
	}

	for _, inbound := range inbounds {
		if skipped[inbound.Id] {
			continue
		}
		clients, ok := parseSettingsClients(inbound.Settings)
		if !ok {
			continue
		}
		for listIndex, entry := range clients {
			email, _ := entry["email"].(string)
			if accountKey(email) == "" {
				continue
			}
			// Check 1: exactly one account, and exactly one membership on this inbound.
			account, found := accountByKey[accountKey(email)]
			if !found {
				return fmt.Errorf("verification failed: inbound %d client %q has no account", inbound.Id, email)
			}
			membership, found := byPair[[2]int{account.Id, inbound.Id}]
			if !found {
				return fmt.Errorf("verification failed: inbound %d client %q has no membership", inbound.Id, email)
			}

			// Check 3: the projection round-trips. Rendering the account back
			// through renderClientEntry must reproduce the stored entry.
			//
			// Compared SEMANTICALLY (deep-equal on the decoded JSON) rather than
			// byte for byte, deliberately. Go marshals map keys in sorted order,
			// so an entry written by an older binary with a different key order,
			// or with a key omitted that decodes to the same zero value, is
			// cosmetically different while being identical in meaning. A
			// byte-identity gate would abort the migration on those and disable
			// the feature for no reason; deep-equal still catches every real
			// difference, which is what this check is for.
			// A KNOWN divergence, already recorded and surfaced in the report.
			// The account deliberately holds the first inbound's values, so this
			// entry cannot match it; that is the merge working, not a bug.
			if conflicted[conflictPair{accountKey(email), inbound.Id}] {
				continue
			}

			rendered := renderClientEntry(account, membership, inbound, entry)
			if !projectionRoundTrips(entry, rendered, listIndex) {
				return fmt.Errorf("verification failed: projection does not round-trip for inbound %d client %q\n  stored:   %s\n  rendered: %s",
					inbound.Id, email, compactJSON(entry), compactJSON(rendered))
			}
		}
	}

	if report.MembershipsCreated > 0 && len(memberships) < totalEntries-report.ClientsSkipped {
		return fmt.Errorf("verification failed: %d memberships for %d client entries", len(memberships), totalEntries-report.ClientsSkipped)
	}
	return nil
}

// projectionRoundTrips reports whether re-rendering an account reproduces the
// client entry it was built from.
//
// It compares EFFECTIVE meaning, not stored bytes, and normalizes exactly two
// fields before comparing. Both normalizations correspond to rules that already
// exist in this codebase, so neither weakens the check:
//
//   - email is folded through accountKey (lower, trimmed), because that is how
//     account identity is compared everywhere else and how normalizeClientEmails
//     already rewrites it on every save. A row predating that normalization can
//     hold "  bob@x.com  " while the account holds "bob@x.com"; those are the
//     same person, and refusing to migrate them would leave the duplicate the
//     feature exists to remove.
//
//   - slot falls back to the LIST INDEX when the stored entry has none, which is
//     slotOr's rule and therefore the address the account is on RIGHT NOW.
//     MigrationAccountSlots normally stamps these before this pass ever runs, so
//     an unstamped row reaching here means an inbound was added in between; the
//     membership carries the same derived value, so nothing moves.
//
// Anything else that differs is a real defect and fails.
func projectionRoundTrips(stored, rendered map[string]any, listIndex int) bool {
	normalized := make(map[string]any, len(stored)+1)
	for k, v := range stored {
		normalized[k] = v
	}
	if email, ok := normalized["email"].(string); ok {
		normalized["email"] = accountKey(email)
	}
	if _, has := normalized["slot"]; !has {
		if _, renderedHasSlot := rendered["slot"]; renderedHasSlot {
			normalized["slot"] = float64(listIndex)
		}
	}

	renderedCopy := make(map[string]any, len(rendered))
	for k, v := range rendered {
		renderedCopy[k] = v
	}
	if email, ok := renderedCopy["email"].(string); ok {
		renderedCopy["email"] = accountKey(email)
	}

	return jsonSemanticEqual(renderedCopy, normalized)
}

// jsonSemanticEqual reports whether two client entries MEAN the same thing.
//
// Deliberately not byte equality and not a bare DeepEqual. Two normalizations
// are applied first, and both are required for this check to be usable on real
// data rather than only on entries this binary happened to write:
//
//  1. Both sides are round-tripped through the encoder. The rendered side holds
//     Go values straight off the Account struct (int64, bool, string) while the
//     stored side holds decoded JSON (float64), so 5 and 5.0 would otherwise
//     compare unequal.
//
//  2. Zero-valued keys are dropped from both sides, because an ABSENT key and a
//     key holding its type's zero are the same thing here. model.Client declares
//     totalGB, expiryTime, limitIp, tgId, reset, subId and comment WITHOUT
//     omitempty, so it unmarshals an absent key to the zero and marshals it back
//     out explicitly. An entry written by an older binary that predates one of
//     those fields is therefore missing keys that the projection now writes as
//     zeros: identical in meaning, different in bytes. Treating that as a
//     mismatch would roll the migration back on essentially every upgraded
//     panel, which is the opposite of what this check is for.
//
// A real difference still fails: an account holding totalGB=0 against an entry
// holding totalGB=100 leaves 100 on one side and nothing on the other.
func jsonSemanticEqual(a, b map[string]any) bool {
	normalize := func(v map[string]any) map[string]any {
		blob, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var decoded map[string]any
		if err := json.Unmarshal(blob, &decoded); err != nil {
			return nil
		}
		out := make(map[string]any, len(decoded))
		for k, value := range decoded {
			if isJSONZero(value) {
				continue
			}
			out[k] = value
		}
		return out
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}

// isJSONZero reports whether a decoded JSON value is indistinguishable from the
// key being absent.
func isJSONZero(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case bool:
		return !t
	case float64:
		return t == 0
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

func compactJSON(v any) string {
	blob, err := json.Marshal(v)
	if err != nil {
		return "<unencodable>"
	}
	return string(blob)
}

// entrySlotOr mirrors slotOr for a raw settings entry.
func entrySlotOr(entry map[string]any, listIndex int) int {
	if v, has := entry["slot"]; has {
		if f, ok := v.(float64); ok && f >= 0 {
			return int(f)
		}
	}
	return listIndex
}

// newAccountFromEntry builds the account row from the first client entry that
// claims an email.
func newAccountFromEntry(entry map[string]any) *model.Account {
	str := func(k string) string { v, _ := entry[k].(string); return v }
	num := func(k string) int64 {
		if f, ok := entry[k].(float64); ok {
			return int64(f)
		}
		return 0
	}
	boolean := func(k string) bool { v, _ := entry[k].(bool); return v }

	return &model.Account{
		Email:      str("email"),
		SubID:      str("subId"),
		TotalGB:    num("totalGB"),
		ExpiryTime: num("expiryTime"),
		Enable:     boolean("enable"),
		Reset:      int(num("reset")),
		LimitIP:    int(num("limitIp")),
		TgID:       num("tgId"),
		Comment:    str("comment"),
	}
}

// mergeAccountFields folds a second entry sharing an email into the account that
// already exists. The FIRST entry (lowest inbound id) always wins; a divergence
// is recorded, never silently merged.
func mergeAccountFields(account *model.Account, entry map[string]any, inboundId int, report *AccountsMigrationReport, conflicted map[conflictPair]bool) {
	record := func(field, old, new string) {
		if old == new {
			return
		}
		report.Conflicts = append(report.Conflicts, AccountMergeConflict{
			Email: account.Email, Field: field, InboundId: inboundId,
			Old: old, New: new, Kept: old,
		})
		conflicted[conflictPair{accountKey(account.Email), inboundId}] = true
	}
	if v, ok := entry["subId"].(string); ok {
		record("subId", account.SubID, v)
	}
	if f, ok := entry["totalGB"].(float64); ok {
		record("totalGB", fmt.Sprint(account.TotalGB), fmt.Sprint(int64(f)))
	}
	if f, ok := entry["expiryTime"].(float64); ok {
		record("expiryTime", fmt.Sprint(account.ExpiryTime), fmt.Sprint(int64(f)))
	}
	if v, ok := entry["enable"].(bool); ok {
		record("enable", fmt.Sprint(account.Enable), fmt.Sprint(v))
	}
}

// extractAccountCredential is the inverse of applyAccountCredential: it lifts the
// credential fields a protocol keys on out of an entry and onto the account.
// Returns whether anything changed, so the caller only writes when needed.
func extractAccountCredential(account *model.Account, entry map[string]any, protocol model.Protocol, inboundId int, report *AccountsMigrationReport, conflicted map[conflictPair]bool) bool {
	str := func(k string) string { v, _ := entry[k].(string); return v }
	changed := false

	set := func(field string, dst *string, value string) {
		if value == "" {
			return
		}
		if *dst == "" {
			*dst = value
			changed = true
			return
		}
		if *dst != value {
			// Two memberships claiming the same credential field differently.
			// The first wins; the second is reported.
			report.Conflicts = append(report.Conflicts, AccountMergeConflict{
				Email: account.Email, Field: field, InboundId: inboundId,
				Old: *dst, New: value, Kept: *dst,
			})
			conflicted[conflictPair{accountKey(account.Email), inboundId}] = true
		}
	}

	switch protocol {
	case model.VMESS:
		set("uuid", &account.UUID, str("id"))
		set("security", &account.Security, str("security"))
	case model.VLESS:
		set("uuid", &account.UUID, str("id"))
	case model.Trojan, model.Shadowsocks, model.ANYTLS:
		set("password", &account.Password, str("password"))
	case model.NAIVE:
		set("password", &account.Password, str("password"))
		set("naiveUsername", &account.NaiveUser, str("username"))
	case model.TUIC:
		set("uuid", &account.UUID, str("id"))
		set("password", &account.Password, str("password"))
	case model.Hysteria, model.Hysteria2:
		set("auth", &account.Auth, str("auth"))
	case model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2, model.SSH:
		set("vpnUsername", &account.VpnUsername, str("id"))
		set("password", &account.Password, str("password"))
	case model.MTPROTO:
		set("secret", &account.Secret, str("secret"))
	case model.WGC, model.AWG, model.GRE:
		// Identity is the email and nothing reads "id"; there is no credential to lift.
	default:
		set("uuid", &account.UUID, str("id"))
	}
	return changed
}

// ensurePreMigrationBackup takes ONE tagged snapshot before the first pass.
//
// Deliberately not SettingService.backupPanelDB: that one is best-effort and
// single-slot (vpn-ui_<version>.db), so a second upgrade from the same version
// silently overwrites the only copy you would want back.
func (s *AccountService) ensurePreMigrationBackup() (string, error) {
	var settingService SettingService
	if existing, err := settingService.getSetting(accountsBackupKey); err == nil && existing != nil && existing.Value != "" {
		if _, statErr := os.Stat(existing.Value); statErr == nil {
			return existing.Value, nil
		}
		// Recorded but gone: take a fresh one rather than trusting the record.
	}

	dbPath := config.GetDBPath()
	if _, err := os.Stat(dbPath); err != nil {
		return "", fmt.Errorf("database %s: %w", dbPath, err)
	}
	dir := filepath.Join(filepath.Dir(dbPath), "backups")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// Fold the WAL into the main DB so the copy is as close to a point-in-time
	// snapshot as a plain file copy can be.
	if gdb := database.GetDB(); gdb != nil {
		if sqlDB, err := gdb.DB(); err == nil {
			_, _ = sqlDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		}
	}
	dst := filepath.Join(dir, fmt.Sprintf("vpn-ui_pre-accounts_%s.db", time.Now().Format("20060102-150405")))
	if err := CopyFile(dbPath, dst); err != nil {
		return "", fmt.Errorf("%s -> %s: %w", dbPath, dst, err)
	}
	for _, side := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(dbPath + side); err != nil {
			continue // checkpointed away or never created
		}
		if err := CopyFile(dbPath+side, dst+side); err != nil {
			return "", fmt.Errorf("%s -> %s: %w", dbPath+side, dst+side, err)
		}
	}
	if err := settingService.setString(accountsBackupKey, dst); err != nil {
		logger.Warning("MigrationAccounts - backup taken but the path could not be recorded: ", err)
	}
	return dst, nil
}

// RevertAccounts drops the accounts layer, putting the panel back on the legacy
// client model. The escape hatch for an operator who does not want this feature
// after all.
//
// It REFUSES when any account holds more than one membership, and that refusal is
// the whole point rather than an inconvenience. settings.clients is still the
// truth, so dropping the tables under a single-membership panel is exactly a
// no-op: every account keeps its entry, its credentials and its address. But an
// account deliberately placed on three inbounds has no non-destructive answer.
// Dropping the tables would leave three settings entries sharing one email and
// one client_traffics row, which is the shape that leaks quota across inbounds
// (each entry would need its own row, and the email is unique). Splitting them
// into three renamed accounts is a real answer but it changes what customers
// were sold. Neither is a decision this command may take silently, so it names
// the accounts and stops.
//
// Returns the number of accounts and memberships removed.
func (s *AccountService) RevertAccounts() (int, int, error) {
	db := database.GetDB()
	if db == nil {
		return 0, 0, fmt.Errorf("no database")
	}

	var multi []model.Account
	err := db.Where("id IN (?)",
		db.Model(&model.AccountInbound{}).
			Select("account_id").
			Group("account_id").
			Having("COUNT(inbound_id) > 1"),
	).Find(&multi).Error
	if err != nil {
		return 0, 0, err
	}
	if len(multi) > 0 {
		names := make([]string, 0, len(multi))
		for i, account := range multi {
			if i == 10 {
				names = append(names, fmt.Sprintf("... and %d more", len(multi)-10))
				break
			}
			names = append(names, account.Email)
		}
		return 0, 0, fmt.Errorf(
			"refusing to revert: %d account(s) are on more than one inbound (%s).\n"+
				"There is no non-destructive way back for those: dropping the tables would leave several settings entries sharing one email and one traffic row, which leaks quota between them.\n"+
				"Put each of them back on a single inbound first (edit the client and untick the extra inbounds), then re-run this.",
			len(multi), strings.Join(names, ", "))
	}

	var accountCount, membershipCount int64
	db.Model(&model.Account{}).Count(&accountCount)
	db.Model(&model.AccountInbound{}).Count(&membershipCount)

	// Ordinary deletes rather than DROP TABLE: AutoMigrate recreates the tables on
	// the next start anyway, and the migration would simply refill them. What this
	// really does is give the operator a clean slate plus the cleared flag, so the
	// next pass starts from scratch.
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&model.AccountInbound{}).Error; err != nil {
			return err
		}
		if err := tx.Where("1 = 1").Delete(&model.Account{}).Error; err != nil {
			return err
		}
		var settingService SettingService
		for _, key := range []string{accountsMigratedKey, accountsReportKey} {
			if err := tx.Where("key = ?", key).Delete(&model.Setting{}).Error; err != nil {
				return err
			}
			_ = settingService
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return int(accountCount), int(membershipCount), nil
}

// GetAccountsMigrationReport returns the stored report, or nil if no pass has
// completed.
func (s *AccountService) GetAccountsMigrationReport() *AccountsMigrationReport {
	var settingService SettingService
	setting, err := settingService.getSetting(accountsReportKey)
	if err != nil || setting == nil || setting.Value == "" {
		return nil
	}
	var report AccountsMigrationReport
	if err := json.Unmarshal([]byte(setting.Value), &report); err != nil {
		return nil
	}
	return &report
}
