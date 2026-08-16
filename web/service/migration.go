package service

import (
	"fmt"
	"io"
	"os"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

// Importing a stock 3x-ui database is a wholesale swap, not a row-by-row merge:
// vpn-ui's schema is a strict superset of stock 3x-ui, and InitDB already carries
// the adopt migrations (promote the lone admin to super admin, adopt ownerless
// inbounds, move global 2FA onto the user) that turn a single-admin stock DB into
// this fork's model. So the whole file replaces the current one and InitDB does
// the translation, exactly the way the backup/restore path (ImportDB) already
// works. See database/db.go InitDB.
//
// The one thing a stock backup must NOT bring with it is how THIS panel is reached
// and how it authenticates: its port, path, listen address, TLS certs, session
// secret, systemd unit name, RADIUS secret and provisioning state describe the
// running install, not the operator's data. Importing a backup's copies of those
// would move the panel out from under the admin doing the import (new port, dead
// TLS, logged-out sessions, broken VPN auth). So they are snapshotted before the
// swap and written back after it; everything else (inbounds, clients, traffic,
// admins, subscription content, Telegram/LDAP config, the xray template with the
// operator's own outbounds and routing) comes across from the backup.
var preservedSettingKeys = []string{
	// How the panel is reached.
	"webListen", "webDomain", "webPort", "webCertFile", "webKeyFile", "webBasePath",
	"subListen", "subDomain", "subPort", "subCertFile", "subKeyFile",
	"subPath", "subJsonPath", "subClashPath",
	// How it authenticates / identifies itself.
	"secret", "sessionMaxAge", "systemdServiceName", "radiusSecret",
	// What has been provisioned on THIS host.
	"vpnProvisioned", "provisionedProtocols",
}

// vpnRangeProtocols are the tunnelled protocols that own per-inbound /24 ranges.
// After importing a vpn-ui backup that carries them, the ranges are re-normalized
// so ownership is non-overlapping on this host. A no-op for a stock 3x-ui backup,
// which has none of these inbounds.
var vpnRangeProtocols = []string{"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wg-c", "awg", "gre"}

// dbFile is what both callers of ImportForeignDB provide: an uploaded multipart
// file (panel) or an *os.File (CLI). Both can be read, seeked, and read-at, which
// is all the signature check and the copy-to-temp need.
type dbFile interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

// ImportReport says what an import landed, for the operator and the dry-run preview.
type ImportReport struct {
	Inbounds          int      `json:"inbounds"`
	Clients           int      `json:"clients"`
	Admins            int      `json:"admins"`
	PreservedSettings []string `json:"preservedSettings"`
}

// ImportForeignDB replaces the current database with an uploaded 3x-ui (or vpn-ui)
// backup, preserving this panel's reachability/identity settings (see
// preservedSettingKeys). activate regenerates daemon configs and restarts Xray; a
// fresh CLI install passes false because the panel is not running yet and its own
// startup will bring services up against the imported data.
//
// The swap is crash-safe: the current DB is moved aside to a .backup and restored
// if any step through InitDB fails, so a failed import never leaves the panel with
// no database. Mirrors ImportDB, which this shares its swap shape with.
func (s *ServerService) ImportForeignDB(src dbFile, activate bool) (*ImportReport, error) {
	// Validate the upload is actually a SQLite file before touching anything.
	isValidDb, err := database.IsSQLiteDB(src)
	if err != nil {
		return nil, common.NewErrorf("Error checking db file format: %v", err)
	}
	if !isValidDb {
		return nil, common.NewError("Invalid db file format")
	}
	if _, err = src.Seek(0, io.SeekStart); err != nil {
		return nil, common.NewErrorf("Error resetting file reader: %v", err)
	}

	// Snapshot the settings that must survive the swap, from the live DB, while it
	// is still the current one. Effective values (a DB row, else the built-in
	// default) so a key that was never written still overwrites the backup's copy.
	preserved := s.snapshotPreservedSettings()

	dbPath := config.GetDBPath()
	tempPath := fmt.Sprintf("%s.temp", dbPath)

	if _, err := os.Stat(tempPath); err == nil {
		if errRemove := os.Remove(tempPath); errRemove != nil {
			return nil, common.NewErrorf("Error removing existing temporary db file: %v", errRemove)
		}
	}
	tempFile, err := os.Create(tempPath)
	if err != nil {
		return nil, common.NewErrorf("Error creating temporary db file: %v", err)
	}
	defer func() {
		if tempFile != nil {
			if cerr := tempFile.Close(); cerr != nil {
				logger.Warningf("import: failed to close temp file: %v", cerr)
			}
		}
		if _, err := os.Stat(tempPath); err == nil {
			if rerr := os.Remove(tempPath); rerr != nil {
				logger.Warningf("import: failed to remove temp file: %v", rerr)
			}
		}
	}()

	if _, err = io.Copy(tempFile, src); err != nil {
		return nil, common.NewErrorf("Error saving db: %v", err)
	}
	if err = tempFile.Close(); err != nil {
		return nil, common.NewErrorf("Error closing temporary db file: %v", err)
	}
	tempFile = nil

	// Structural integrity of the upload, before it can replace a working DB.
	if err = database.ValidateSQLiteDB(tempPath); err != nil {
		return nil, common.NewErrorf("Invalid or corrupt db file: %v", err)
	}

	if errStop := s.StopXrayService(); errStop != nil {
		logger.Warningf("import: failed to stop Xray before DB import: %v", errStop)
	}
	if errClose := database.CloseDB(); errClose != nil {
		logger.Warningf("import: failed to close existing DB before replacement: %v", errClose)
	}

	fallbackPath := fmt.Sprintf("%s.backup", dbPath)
	if _, err := os.Stat(fallbackPath); err == nil {
		if errRemove := os.Remove(fallbackPath); errRemove != nil {
			return nil, common.NewErrorf("Error removing existing fallback db file: %v", errRemove)
		}
	}
	if err = os.Rename(dbPath, fallbackPath); err != nil {
		return nil, common.NewErrorf("Error backing up current db file: %v", err)
	}
	// See the identical call in ServerService.ImportDB: the sidecars stay at the
	// old path and must not be inherited by the imported database.
	database.RemoveSidecars(dbPath)
	defer func() {
		// Only fires on the success path; the fallback is consumed by an error return.
		if _, err := os.Stat(fallbackPath); err == nil {
			if rerr := os.Remove(fallbackPath); rerr != nil {
				logger.Warningf("import: failed to remove fallback file: %v", rerr)
			}
		}
	}()

	if err = os.Rename(tempPath, dbPath); err != nil {
		if errRename := os.Rename(fallbackPath, dbPath); errRename != nil {
			return nil, common.NewErrorf("Error moving db file and restoring fallback: %v", errRename)
		}
		return nil, common.NewErrorf("Error moving db file: %v", err)
	}

	// AutoMigrate the superset schema onto the backup and run the adopt migrations.
	if err = database.InitDB(dbPath); err != nil {
		if errRename := os.Rename(fallbackPath, dbPath); errRename != nil {
			return nil, common.NewErrorf("Error migrating db and restoring fallback: %v", errRename)
		}
		if errReinit := database.InitDB(dbPath); errReinit != nil {
			logger.Errorf("import: restored fallback but re-init failed: %v", errReinit)
		}
		return nil, common.NewErrorf("Error migrating db: %v", err)
	}

	// Put this panel's reachability/identity settings back over the backup's.
	if err = s.restorePreservedSettings(preserved); err != nil {
		return nil, common.NewErrorf("Imported DB but failed to preserve panel settings: %v", err)
	}

	s.inboundService.MigrateDB()

	report := s.buildImportReport(preserved)

	if activate {
		// Re-normalize tunnelled-protocol ranges for this host and bring the data
		// plane up against the imported inbounds.
		for _, proto := range vpnRangeProtocols {
			AutoExpandVpnRanges(proto)
		}
		s.l2tpService.InitL2tp()
		s.pptpService.InitPptp()
		if err = s.RestartXrayService(); err != nil {
			return report, common.NewErrorf("Imported DB but failed to start Xray: %v", err)
		}
	}

	return report, nil
}

// snapshotPreservedSettings reads the effective value of each preserved key: the
// stored row if present, else the built-in default. A key with neither (e.g.
// radiusSecret on a never-provisioned box) is simply absent from the snapshot and
// is left as the backup has it.
func (s *ServerService) snapshotPreservedSettings() map[string]string {
	db := database.GetDB()
	var rows []model.Setting
	if err := db.Where("key IN ?", preservedSettingKeys).Find(&rows).Error; err != nil {
		logger.Warningf("import: could not read current settings to preserve: %v", err)
	}
	stored := make(map[string]string, len(rows))
	for _, r := range rows {
		stored[r.Key] = r.Value
	}
	out := make(map[string]string, len(preservedSettingKeys))
	for _, key := range preservedSettingKeys {
		if v, ok := stored[key]; ok {
			out[key] = v
		} else if v, ok := defaultValueMap[key]; ok {
			out[key] = v
		}
	}
	return out
}

// restorePreservedSettings upserts the snapshot into the freshly imported DB.
func (s *ServerService) restorePreservedSettings(preserved map[string]string) error {
	db := database.GetDB()
	return db.Transaction(func(tx *gorm.DB) error {
		for key, value := range preserved {
			setting := &model.Setting{}
			err := tx.Where("key = ?", key).First(setting).Error
			switch {
			case err == nil:
				setting.Value = value
				if err := tx.Save(setting).Error; err != nil {
					return err
				}
			case database.IsNotFound(err):
				if err := tx.Create(&model.Setting{Key: key, Value: value}).Error; err != nil {
					return err
				}
			default:
				return err
			}
		}
		return nil
	})
}

func (s *ServerService) buildImportReport(preserved map[string]string) *ImportReport {
	db := database.GetDB()
	report := &ImportReport{PreservedSettings: make([]string, 0, len(preserved))}
	// Report in the stable declared order rather than map order.
	for _, key := range preservedSettingKeys {
		if _, ok := preserved[key]; ok {
			report.PreservedSettings = append(report.PreservedSettings, key)
		}
	}
	var n int64
	if err := db.Model(&model.Inbound{}).Count(&n).Error; err == nil {
		report.Inbounds = int(n)
	}
	if err := db.Model(&xray.ClientTraffic{}).Count(&n).Error; err == nil {
		report.Clients = int(n)
	}
	if err := db.Model(&model.User{}).Count(&n).Error; err == nil {
		report.Admins = int(n)
	}
	return report
}
