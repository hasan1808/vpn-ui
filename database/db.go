// Package database provides database initialization, migration, and management utilities
// for the vpn-ui panel using GORM with SQLite.
package database

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"path"
	"slices"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/util/crypto"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

const (
	defaultUsername = "admin"
	defaultPassword = "admin"
)

func initModels() error {
	models := []any{
		&model.User{},
		&model.Inbound{},
		&model.InboundAccess{},
		&model.ResellerProfile{},
		&model.ResellerClient{},
		// The accounts layer. Creating these is purely additive: an old binary rolled
		// back onto a migrated database ignores both tables (AutoMigrate never drops
		// what it does not know) and keeps reading settings.clients exactly as before.
		&model.Account{},
		&model.AccountInbound{},
		&model.OutboundTraffics{},
		&model.Setting{},
		&model.InboundClientIps{},
		&xray.ClientTraffic{},
		&model.HistoryOfSeeders{},
		&model.CustomGeoResource{},
	}
	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			log.Printf("Error auto migrating model: %v", err)
			return err
		}
	}
	return nil
}

// migrateProtocolSlugs rewrites renamed protocol identifiers in existing inbound rows so
// they keep matching the code after a slug rename. WireGuard (C) was originally stored as
// "wgvpn"; it is now "wg-c". Best-effort: a failure just leaves the row untouched (the
// inbound would then be unmanaged until re-created), so it never blocks startup.
func migrateProtocolSlugs() {
	renames := map[string]string{"wgvpn": "wg-c"}
	for old, cur := range renames {
		if err := db.Model(&model.Inbound{}).Where("protocol = ?", old).Update("protocol", cur).Error; err != nil {
			log.Printf("protocol slug migration %s -> %s skipped: %v", old, cur, err)
		}
	}
}

// initUser creates a default admin user if the users table is empty.
func initUser() error {
	empty, err := isTableEmpty("users")
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		return err
	}
	if empty {
		hashedPassword, err := crypto.HashPasswordAsBcrypt(defaultPassword)

		if err != nil {
			log.Printf("Error hashing default password: %v", err)
			return err
		}

		user := &model.User{
			Username:     defaultUsername,
			Password:     hashedPassword,
			IsSuperAdmin: true,
			Enable:       true,
		}
		return db.Create(user).Error
	}
	return nil
}

// migrateSuperAdmin promotes the pre-existing admin on upgrade.
//
// The multi-admin columns land via AutoMigrate defaulting to is_super_admin=0 and
// permissions=0, which would leave an upgraded panel with an admin who can log in
// but do nothing and cannot grant themselves anything back. So the lowest-id user
// (the historic GetFirstUser, which was the panel's implicit root) is promoted,
// and any account predating the Enable column is switched on.
//
// Guarded on there being no super admin at all, which makes it idempotent and
// stops it from re-promoting an account a super admin later demoted on purpose.
func migrateSuperAdmin() {
	var supers int64
	if err := db.Model(&model.User{}).Where("is_super_admin = ?", true).Count(&supers).Error; err != nil {
		log.Printf("super-admin migration skipped: %v", err)
		return
	}
	if supers > 0 {
		return
	}
	first := &model.User{}
	if err := db.Model(&model.User{}).Order("id asc").First(first).Error; err != nil {
		return // no users yet; initUser seeds one as super admin
	}
	if err := db.Model(&model.User{}).Where("id = ?", first.Id).
		Updates(map[string]any{"is_super_admin": true, "enable": true}).Error; err != nil {
		log.Printf("promoting user %d to super admin failed: %v", first.Id, err)
		return
	}
	log.Printf("multi-admin migration: promoted user %q (id %d) to super admin", first.Username, first.Id)
}

// migrateGlobalTwoFactor moves the old panel-wide 2FA onto the super admin.
//
// 2FA used to be one shared secret in the settings table. It is now per-admin, so
// without this an upgrade would silently drop the second factor off an account
// that had deliberately enabled it.
//
// The old settings rows are then CLEARED, not left behind. They are not inert: the
// secret is now the super admin's live second factor, and GetAllSetting serves the
// whole settings table to any admin holding accessPanelSettings, so leaving it
// would hand a sub-admin the super admin's TOTP.
func migrateGlobalTwoFactor() {
	var enable, token model.Setting
	if err := db.Where("key = ?", "twoFactorEnable").First(&enable).Error; err != nil {
		return // never configured
	}
	if enable.Value != "true" {
		return
	}
	if err := db.Where("key = ?", "twoFactorToken").First(&token).Error; err != nil || token.Value == "" {
		return
	}
	super := &model.User{}
	if err := db.Model(&model.User{}).Where("is_super_admin = ?", true).Order("id asc").First(super).Error; err != nil {
		return
	}
	// Copy it over unless the admin already has their own. Deliberately NOT an early
	// return: an earlier build of this migration copied the secret and left the
	// settings rows, so a panel upgraded through that build sits here with
	// TwoFactorEnable already true AND the shared copy still being served. The
	// clearing below has to run either way.
	if !super.TwoFactorEnable {
		err := db.Model(&model.User{}).Where("id = ?", super.Id).Updates(map[string]any{
			"two_factor_enable": true,
			"two_factor_token":  token.Value,
		}).Error
		if err != nil {
			log.Printf("migrating global 2FA to super admin failed: %v", err)
			return
		}
		log.Printf("multi-admin migration: moved panel-wide 2FA onto super admin %q", super.Username)
	}
	// Clear the shared copy now it has an owner. Unconditional: it is the super
	// admin's live second factor and GetAllSetting serves it to anyone holding
	// accessPanelSettings.
	if err := db.Model(&model.Setting{}).Where("key IN ?", []string{"twoFactorEnable", "twoFactorToken"}).
		Update("value", "").Error; err != nil {
		log.Printf("clearing the migrated global 2FA settings failed: %v", err)
	}
}

// migrateInboundOwners assigns ownerless inbounds to the super admin.
//
// GetInbounds has always filtered by user_id; it looked inert only because every
// row carried the single admin's id. Any row with user_id=0 (or pointing at a user
// that no longer exists) would render in nobody's list once a second admin exists,
// so it is adopted by the super admin rather than being silently orphaned.
func migrateInboundOwners() {
	super := &model.User{}
	if err := db.Model(&model.User{}).Where("is_super_admin = ?", true).Order("id asc").First(super).Error; err != nil {
		return
	}
	var ids []int
	if err := db.Model(&model.User{}).Pluck("id", &ids).Error; err != nil {
		return
	}
	// GORM renders an empty slice as `NOT IN (NULL)`, which is NULL for every row and
	// therefore never true, so the statement would silently adopt nothing. Cannot
	// happen today (the super-admin lookup above guarantees at least one id), but the
	// guard that saves it is incidental and one refactor from being removed.
	if len(ids) == 0 {
		return
	}
	res := db.Model(&model.Inbound{}).Where("user_id NOT IN (?) OR user_id IS NULL", ids).
		Update("user_id", super.Id)
	if res.Error != nil {
		log.Printf("adopting ownerless inbounds failed: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("multi-admin migration: assigned %d ownerless inbound(s) to super admin %q",
			res.RowsAffected, super.Username)
	}
}

// migrateInboundAccess seeds the access table from the existing creator column.
//
// Access used to be implied by Inbound.UserId (you saw what you created). It is now
// assigned explicitly, so without this an upgrade would hide every existing inbound
// from the admin who made it: the assignment table starts empty and empty means no
// access. Grants each non-super admin their own rows, once.
//
// Guarded on the table being empty rather than per-row, so a super admin who later
// REVOKES an inbound does not have it silently granted back on the next restart.
func migrateInboundAccess() {
	empty, err := isTableEmpty("inbound_accesses")
	if err != nil || !empty {
		return
	}
	var inbounds []*model.Inbound
	if err := db.Model(&model.Inbound{}).Find(&inbounds).Error; err != nil {
		return
	}
	supers := map[int]bool{}
	var superIds []int
	if err := db.Model(&model.User{}).Where("is_super_admin = ?", true).Pluck("id", &superIds).Error; err == nil {
		for _, id := range superIds {
			supers[id] = true
		}
	}
	granted := 0
	for _, ib := range inbounds {
		// Super admins see everything by role, so an explicit grant would be noise.
		if ib.UserId <= 0 || supers[ib.UserId] {
			continue
		}
		if err := db.Create(&model.InboundAccess{UserId: ib.UserId, InboundId: ib.Id}).Error; err != nil {
			log.Printf("seeding inbound access for inbound %d: %v", ib.Id, err)
			continue
		}
		granted++
	}
	if granted > 0 {
		log.Printf("multi-admin migration: granted %d existing inbound(s) to their creators", granted)
	}
}

// runSeeders migrates user passwords to bcrypt and records seeder execution to prevent re-running.
func runSeeders(isUsersEmpty bool) error {
	empty, err := isTableEmpty("history_of_seeders")
	if err != nil {
		log.Printf("Error checking if history_of_seeders table is empty: %v", err)
		return err
	}

	if empty && isUsersEmpty {
		hashSeeder := &model.HistoryOfSeeders{
			SeederName: "UserPasswordHash",
		}
		return db.Create(hashSeeder).Error
	} else {
		var seedersHistory []string
		db.Model(&model.HistoryOfSeeders{}).Pluck("seeder_name", &seedersHistory)

		if !slices.Contains(seedersHistory, "UserPasswordHash") && !isUsersEmpty {
			var users []model.User
			db.Find(&users)

			for _, user := range users {
				hashedPassword, err := crypto.HashPasswordAsBcrypt(user.Password)
				if err != nil {
					log.Printf("Error hashing password for user '%s': %v", user.Username, err)
					return err
				}
				db.Model(&user).Update("password", hashedPassword)
			}

			hashSeeder := &model.HistoryOfSeeders{
				SeederName: "UserPasswordHash",
			}
			return db.Create(hashSeeder).Error
		}
	}

	return nil
}

// isTableEmpty returns true if the named table contains zero rows.
func isTableEmpty(tableName string) (bool, error) {
	var count int64
	err := db.Table(tableName).Count(&count).Error
	return count == 0, err
}

// sqliteDSNParams are appended to the database path when opening it.
//
// WAL is the entire point. Without it SQLite uses the rollback journal, where a
// writer blocks every reader for the whole transaction - and this panel writes
// constantly: the traffic job every 10s, the IP job every 10s, the speed-limit
// job every second, each overlapping ordinary page loads, the subscription server
// and RADIUS auth. The driver defaults busy_timeout to 5s, so the symptom was
// never an error in the log; readers just stalled, which reads as "the panel is
// slow" rather than as a bug. Measured on this workload: reads go from ~40/s with
// multi-second stalls to ~5,100/s with single-digit-ms worst case.
//
// The rest of the file already assumes WAL and was dead code until now: the
// backup paths checkpoint and copy the -wal/-shm sidecars (main.go,
// panelupdate.go, deploy.sh), and migrateLegacyDB moves them.
//
// synchronous=NORMAL is safe under WAL: a power loss can cost the last
// transaction but cannot corrupt the file. busy_timeout raises the driver's own
// 5s default.
//
// Deliberately NOT set: cache=shared (measured no gain, and it reintroduces
// cross-connection table locking) and foreign_keys=ON (a behaviour change on an
// existing database, unrelated to this fix). Do not add SetMaxOpenConns(1)
// either - it halves read throughput.
//
// The file format is unchanged, so DB export/import, the SQLite magic sniff, and
// stock 3x-ui imports all keep working. Caveat: WAL does not work on network
// filesystems, which matters only if VPNUI_DB_FOLDER points at an NFS/CIFS mount.
const sqliteDSNParams = "?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000"

// InitDB sets up the database connection, migrates models, and runs seeders.
// migrateLegacyDB moves a database (plus its sqlite sidecar files) from a prior
// location/name to the current path when the current one doesn't exist yet, so
// upgrades keep their users and inbounds. It tries each legacy candidate in order
// and migrates the first that exists. Best-effort: any failure just leaves a
// fresh DB to be created at the new path.
func migrateLegacyDB(dbPath string) {
	if _, err := os.Stat(dbPath); err == nil {
		return // current DB already present — nothing to migrate
	}
	for _, legacy := range config.LegacyDBPaths() {
		if legacy == dbPath {
			continue
		}
		if _, err := os.Stat(legacy); err != nil {
			continue // this legacy DB doesn't exist — try the next
		}
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			src, dst := legacy+suffix, dbPath+suffix
			if _, err := os.Stat(src); err != nil {
				continue
			}
			if err := os.Rename(src, dst); err != nil {
				// Different filesystem (e.g. /etc vs /root on separate mounts): copy.
				if copyFile(src, dst) == nil {
					_ = os.Remove(src)
				}
			}
		}
		log.Printf("migrated database from %s to %s", legacy, dbPath)
		return
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func InitDB(dbPath string) error {
	dir := path.Dir(dbPath)
	err := os.MkdirAll(dir, 0750)
	if err != nil {
		return err
	}

	migrateLegacyDB(dbPath)

	var gormLogger logger.Interface

	if config.IsDebug() {
		gormLogger = logger.Default
	} else {
		gormLogger = logger.Discard
	}

	c := &gorm.Config{
		Logger: gormLogger,
	}
	db, err = gorm.Open(sqlite.Open(dbPath+sqliteDSNParams), c)
	if err != nil {
		return err
	}

	if err := initModels(); err != nil {
		return err
	}

	migrateProtocolSlugs()

	isUsersEmpty, err := isTableEmpty("users")
	if err != nil {
		return err
	}

	if err := initUser(); err != nil {
		return err
	}
	// Order matters: promote a super admin before adopting inbounds, since the
	// adoption needs an owner to assign them to.
	migrateSuperAdmin()
	migrateGlobalTwoFactor()
	migrateInboundOwners()
	migrateInboundAccess()
	return runSeeders(isUsersEmpty)
}

// GetSettingValue opens the DB and returns a single `settings` value via a plain
// read-only SELECT — NO AutoMigrate and NO seeders (unlike InitDB). This lets a
// short-lived hook process (e.g. `vpn-ui openvpn-auth`, which runs on every login
// alongside the live panel) read a setting without migrating/seeding/locking the DB
// the panel owns. A busy timeout tolerates the panel writing concurrently; a missing
// key yields ("", nil).
func GetSettingValue(dbPath, key string) (string, error) {
	rdb, err := gorm.Open(sqlite.Open(dbPath+"?_busy_timeout=3000"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return "", err
	}
	if sqlDB, e := rdb.DB(); e == nil {
		defer sqlDB.Close()
	}
	var value string
	err = rdb.Raw("SELECT value FROM settings WHERE key = ?", key).Scan(&value).Error
	return value, err
}

// CloseDB closes the database connection if it exists.
func CloseDB() error {
	if db != nil {
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

// GetDB returns the global GORM database instance.
func GetDB() *gorm.DB {
	return db
}

func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}

// IsSQLiteDB checks if the given file is a valid SQLite database by reading its signature.
func IsSQLiteDB(file io.ReaderAt) (bool, error) {
	signature := []byte("SQLite format 3\x00")
	buf := make([]byte, len(signature))
	_, err := file.ReadAt(buf, 0)
	if err != nil {
		return false, err
	}
	return bytes.Equal(buf, signature), nil
}

// Checkpoint folds the WAL back into the main database file.
//
// TRUNCATE, not the default PASSIVE. The caller is ServerService.GetDb, which
// checkpoints and then serves ONLY the .db file as the panel's DB download. A
// passive checkpoint yields to any concurrent reader and still reports success,
// so on a busy panel the downloaded backup could quietly be missing the most
// recent writes - the one thing a backup may not do. The other two backup paths
// (main.go, panelupdate.go) already use TRUNCATE; this one was the odd one out.
func Checkpoint() error {
	return db.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error
}

// RemoveSidecars deletes the -wal/-shm files belonging to dbPath.
//
// Needed wherever a database file is swapped out: the sidecars are named after
// the PATH, not the file, so leaving them next to a freshly imported database
// pairs a foreign WAL with it, which is a documented corruption path. Closing the
// DB normally removes them, but that close is best-effort in both import paths
// (the error is logged, not fatal) and a crash mid-import leaves them behind.
// Missing files are not an error.
func RemoveSidecars(dbPath string) {
	// log, not the project logger: `logger` in this file is gorm's.
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !os.IsNotExist(err) {
			log.Printf("database: could not remove %s%s: %v", dbPath, suffix, err)
		}
	}
}

// ValidateSQLiteDB opens the provided sqlite DB path with a throw-away connection
// and runs a PRAGMA integrity_check to ensure the file is structurally sound.
// It does not mutate global state or run migrations.
func ValidateSQLiteDB(dbPath string) error {
	if _, err := os.Stat(dbPath); err != nil { // file must exist
		return err
	}
	gdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	var res string
	if err := gdb.Raw("PRAGMA integrity_check;").Scan(&res).Error; err != nil {
		return err
	}
	if res != "ok" {
		return errors.New("sqlite integrity check failed: " + res)
	}
	return nil
}

// MigrateSuperAdminForTest exposes the super-admin promotion so tests can drive
// the upgrade path against an already-open DB.
func MigrateSuperAdminForTest() { migrateSuperAdmin() }

// MigrateGlobalTwoFactorForTest exposes the 2FA migration so tests can drive the
// upgrade path against an already-open DB.
func MigrateGlobalTwoFactorForTest() { migrateGlobalTwoFactor() }
