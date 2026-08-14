package service

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/util/random"
	"github.com/mhsanaei/3x-ui/v2/util/reflect_util"
	"github.com/mhsanaei/3x-ui/v2/web/entity"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

//go:embed config.json
var xrayTemplateConfig string

var defaultValueMap = map[string]string{
	"xrayTemplateConfig":          xrayTemplateConfig,
	"webListen":                   "",
	"webDomain":                   "",
	"publicIp":                    "",
	"webPort":                     "2083",
	"webCertFile":                 "",
	"webKeyFile":                  "",
	"secret":                      random.Seq(32),
	"webBasePath":                 "/",
	"sessionMaxAge":               "360",
	"pageSize":                    "25",
	"expireDiff":                  "0",
	"trafficDiff":                 "0",
	"remarkModel":                 "-ieo",
	"serverName":                  "",
	"timeLocation":                "Local",
	"tgBotEnable":                 "false",
	"tgBotToken":                  "",
	"tgBotProxy":                  "",
	"tgBotAPIServer":              "",
	"tgBotChatId":                 "",
	"tgRunTime":                   "@daily",
	"tgBotBackup":                 "false",
	"tgBotLoginNotify":            "true",
	"tgCpu":                       "80",
	"tgLang":                      "en-US",
	"twoFactorEnable":             "false",
	"twoFactorToken":              "",
	"systemdServiceName":          "vpn-ui",
	"subEnable":                   "false",
	"subJsonEnable":               "false",
	"subTitle":                    "",
	"subSupportUrl":               "",
	"subProfileUrl":               "",
	"subAnnounce":                 "",
	"subEnableRouting":            "true",
	"subRoutingRules":             "",
	"subListen":                   "",
	"subPort":                     "2097",
	"subPath":                     "/sub/",
	"subDomain":                   "",
	"subCertFile":                 "",
	"subKeyFile":                  "",
	"subUpdates":                  "12",
	"subEncrypt":                  "true",
	"subShowInfo":                 "true",
	"subURI":                      "",
	"subJsonPath":                 "/json/",
	"subJsonURI":                  "",
	"subClashEnable":              "true",
	"subClashPath":                "/clash/",
	"subClashURI":                 "",
	"subJsonFragment":             "",
	"subJsonNoises":               "",
	"subJsonMux":                  "",
	"subJsonRules":                "",
	"subTemplate":                 "base64",
	"subCustomTemplate":           "",
	"datepicker":                  "gregorian",
	"warp":                        "",
	"nord":                        "",
	"externalTrafficInformEnable": "false",
	"externalTrafficInformURI":    "",
	"xrayOutboundTestUrl":         "https://www.google.com/generate_204",

	// LDAP defaults
	"ldapEnable":            "false",
	"ldapHost":              "",
	"ldapPort":              "389",
	"ldapUseTLS":            "false",
	"ldapBindDN":            "",
	"ldapPassword":          "",
	"ldapBaseDN":            "",
	"ldapUserFilter":        "(objectClass=person)",
	"ldapUserAttr":          "mail",
	"ldapVlessField":        "vless_enabled",
	"ldapSyncCron":          "@every 1m",
	"ldapFlagField":         "",
	"ldapTruthyValues":      "true,1,yes,on",
	"ldapInvertFlag":        "false",
	"ldapInboundTags":       "",
	"ldapAutoCreate":        "false",
	"ldapAutoDelete":        "false",
	"ldapDefaultTotalGB":    "0",
	"ldapDefaultExpiryDays": "0",
	"ldapDefaultLimitIP":    "0",
	"vpnProvisioned":        "false",
	"provisionedProtocols":  "",
	// The version an in-panel self-update replaced, written just before the
	// restart and cleared by the first super admin to be told about it. See
	// SettingService.TakePanelUpdatedFrom.
	"panelUpdatedFrom": "",
	// Marks that the one-time grant of PermAccessOverview to the admins who
	// predate that bit has run. See AdminService.MigrationOverviewAccess.
	"overviewAccessBackfilled": "false",
	// Operator-configured SSH egress tunnels (JSON array); see web/service/sshoutbound.go.
	"sshOutbounds": "",
	// Operator-configured VPN client tunnels used as egress (JSON array); see
	// web/service/vpnoutbound.go. Declared here because getString treats a key absent
	// from this map as an ERROR rather than as "unset": until the first save writes a
	// row, every read of an undeclared key comes back as a failure, and the reader can
	// no longer tell "no tunnels configured" from "the settings table is unreadable".
	"vpnOutbounds": "",

	// Auto SSL / Let's Encrypt defaults
	"acmeEnable":    "false",
	"acmeDomain":    "",
	"acmeEmail":     "",
	"acmeMethod":    "http",
	"acmeCfToken":   "",
	"acmeCertDir":   "/root/.acme.sh/certs/panel",
	"acmeAutoRenew": "true",
}

// SettingService provides business logic for application settings management.
// It handles configuration storage, retrieval, and validation for all system settings.
type SettingService struct{}

func (s *SettingService) GetDefaultJSONConfig() (any, error) {
	var jsonData any
	err := json.Unmarshal([]byte(xrayTemplateConfig), &jsonData)
	if err != nil {
		return nil, err
	}
	return jsonData, nil
}

func (s *SettingService) GetAllSetting() (*entity.AllSetting, error) {
	db := database.GetDB()
	settings := make([]*model.Setting, 0)
	err := db.Model(model.Setting{}).Not("key = ?", "xrayTemplateConfig").Find(&settings).Error
	if err != nil {
		return nil, err
	}
	allSetting := &entity.AllSetting{}
	t := reflect.TypeFor[entity.AllSetting]()
	v := reflect.ValueOf(allSetting).Elem()
	fields := reflect_util.GetFields(t)

	setSetting := func(key, value string) (err error) {
		defer func() {
			panicErr := recover()
			if panicErr != nil {
				err = errors.New(fmt.Sprint(panicErr))
			}
		}()

		var found bool
		var field reflect.StructField
		for _, f := range fields {
			if f.Tag.Get("json") == key {
				field = f
				found = true
				break
			}
		}

		if !found {
			// Some settings are automatically generated, no need to return to the front end to modify the user
			return nil
		}

		fieldV := v.FieldByName(field.Name)
		switch fieldV.Interface().(type) {
		case int:
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return err
			}
			fieldV.SetInt(n)
		case string:
			fieldV.SetString(value)
		case bool:
			fieldV.SetBool(value == "true")
		default:
			return common.NewErrorf("unknown field %v type %v", key, reflect.TypeOf(fieldV.Interface()))
		}
		return
	}

	keyMap := map[string]bool{}
	for _, setting := range settings {
		err := setSetting(setting.Key, setting.Value)
		if err != nil {
			return nil, err
		}
		keyMap[setting.Key] = true
	}

	for key, value := range defaultValueMap {
		if keyMap[key] {
			continue
		}
		err := setSetting(key, value)
		if err != nil {
			return nil, err
		}
	}

	return allSetting, nil
}

func (s *SettingService) ResetSettings() error {
	db := database.GetDB()
	err := db.Where("1 = 1").Delete(model.Setting{}).Error
	if err != nil {
		return err
	}
	return db.Where("1 = 1").Delete(model.User{}).Error
}

func (s *SettingService) getSetting(key string) (*model.Setting, error) {
	db := database.GetDB()
	setting := &model.Setting{}
	err := db.Model(model.Setting{}).Where("key = ?", key).First(setting).Error
	if err != nil {
		return nil, err
	}
	return setting, nil
}

func (s *SettingService) saveSetting(key string, value string) error {
	setting, err := s.getSetting(key)
	db := database.GetDB()
	if database.IsNotFound(err) {
		return db.Create(&model.Setting{
			Key:   key,
			Value: value,
		}).Error
	} else if err != nil {
		return err
	}
	setting.Key = key
	setting.Value = value
	return db.Save(setting).Error
}

func (s *SettingService) getString(key string) (string, error) {
	setting, err := s.getSetting(key)
	if database.IsNotFound(err) {
		value, ok := defaultValueMap[key]
		if !ok {
			return "", common.NewErrorf("key <%v> not in defaultValueMap", key)
		}
		return value, nil
	} else if err != nil {
		return "", err
	}
	return setting.Value, nil
}

func (s *SettingService) setString(key string, value string) error {
	return s.saveSetting(key, value)
}

func (s *SettingService) getBool(key string) (bool, error) {
	str, err := s.getString(key)
	if err != nil {
		return false, err
	}
	return strconv.ParseBool(str)
}

func (s *SettingService) setBool(key string, value bool) error {
	return s.setString(key, strconv.FormatBool(value))
}

func (s *SettingService) getInt(key string) (int, error) {
	str, err := s.getString(key)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(str)
}

func (s *SettingService) setInt(key string, value int) error {
	return s.setString(key, strconv.Itoa(value))
}

func (s *SettingService) GetXrayConfigTemplate() (string, error) {
	return s.getString("xrayTemplateConfig")
}

func (s *SettingService) GetXrayOutboundTestUrl() (string, error) {
	return s.getString("xrayOutboundTestUrl")
}

func (s *SettingService) SetXrayOutboundTestUrl(url string) error {
	return s.setString("xrayOutboundTestUrl", url)
}

// outboundStatusKey persists the last outbound test results (keyed by tag) so
// the Xray page and the dashboard can render connectivity after a reload.
const outboundStatusKey = "outboundStatus"

// GetOutboundStatuses returns the persisted outbound test results keyed by tag.
// It never errors on a missing or corrupt value; both just yield an empty map.
func (s *SettingService) GetOutboundStatuses() (map[string]*OutboundStatus, error) {
	statuses := make(map[string]*OutboundStatus)
	setting, err := s.getSetting(outboundStatusKey)
	if database.IsNotFound(err) || err != nil {
		return statuses, nil
	}
	if setting.Value == "" {
		return statuses, nil
	}
	if err := json.Unmarshal([]byte(setting.Value), &statuses); err != nil {
		return statuses, nil
	}
	return statuses, nil
}

// SaveOutboundStatus records the latest test result for one outbound tag.
func (s *SettingService) SaveOutboundStatus(tag string, status *OutboundStatus) error {
	statuses, err := s.GetOutboundStatuses()
	if err != nil {
		statuses = make(map[string]*OutboundStatus)
	}
	statuses[tag] = status
	data, err := json.Marshal(statuses)
	if err != nil {
		return err
	}
	return s.saveSetting(outboundStatusKey, string(data))
}

func (s *SettingService) GetListen() (string, error) {
	return s.getString("webListen")
}

func (s *SettingService) SetListen(ip string) error {
	return s.setString("webListen", ip)
}

func (s *SettingService) GetWebDomain() (string, error) {
	return s.getString("webDomain")
}

func (s *SettingService) GetTgBotToken() (string, error) {
	return s.getString("tgBotToken")
}

func (s *SettingService) SetTgBotToken(token string) error {
	return s.setString("tgBotToken", token)
}

func (s *SettingService) GetTgBotProxy() (string, error) {
	return s.getString("tgBotProxy")
}

func (s *SettingService) SetTgBotProxy(token string) error {
	return s.setString("tgBotProxy", token)
}

func (s *SettingService) GetTgBotAPIServer() (string, error) {
	return s.getString("tgBotAPIServer")
}

func (s *SettingService) SetTgBotAPIServer(token string) error {
	return s.setString("tgBotAPIServer", token)
}

func (s *SettingService) GetTgBotChatId() (string, error) {
	return s.getString("tgBotChatId")
}

func (s *SettingService) SetTgBotChatId(chatIds string) error {
	return s.setString("tgBotChatId", chatIds)
}

func (s *SettingService) GetTgbotEnabled() (bool, error) {
	return s.getBool("tgBotEnable")
}

func (s *SettingService) SetTgbotEnabled(value bool) error {
	return s.setBool("tgBotEnable", value)
}

func (s *SettingService) GetTgbotRuntime() (string, error) {
	return s.getString("tgRunTime")
}

func (s *SettingService) SetTgbotRuntime(time string) error {
	return s.setString("tgRunTime", time)
}

func (s *SettingService) GetTgBotBackup() (bool, error) {
	return s.getBool("tgBotBackup")
}

func (s *SettingService) GetTgBotLoginNotify() (bool, error) {
	return s.getBool("tgBotLoginNotify")
}

func (s *SettingService) GetTgCpu() (int, error) {
	return s.getInt("tgCpu")
}

func (s *SettingService) GetTgLang() (string, error) {
	return s.getString("tgLang")
}

func (s *SettingService) GetTwoFactorEnable() (bool, error) {
	return s.getBool("twoFactorEnable")
}

func (s *SettingService) SetTwoFactorEnable(value bool) error {
	return s.setBool("twoFactorEnable", value)
}

// GetVpnProvisioned reports whether the VPN backend has been provisioned via the
// Core Settings "Initialize Setup" flow. Any error (missing key, parse) is
// treated as not-provisioned so a fresh install shows the setup call-to-action.
func (s *SettingService) GetVpnProvisioned() bool {
	v, err := s.getBool("vpnProvisioned")
	if err != nil {
		return false
	}
	return v
}

// SetVpnProvisioned persists whether the VPN backend has been provisioned.
func (s *SettingService) SetVpnProvisioned(value bool) error {
	return s.setBool("vpnProvisioned", value)
}

// GetOverviewAccessBackfilled reports whether the one-time PermAccessOverview grant
// has already run on this install. A read error is treated as "already done" so a
// broken settings table can never re-grant a permission an operator revoked; the
// backfill exists to preserve the old behaviour once, not to keep restoring it.
func (s *SettingService) GetOverviewAccessBackfilled() bool {
	v, err := s.getBool("overviewAccessBackfilled")
	if err != nil {
		return true
	}
	return v
}

// SetOverviewAccessBackfilled records that the one-time grant has run.
func (s *SettingService) SetOverviewAccessBackfilled(value bool) error {
	return s.setBool("overviewAccessBackfilled", value)
}

// SetPanelUpdatedFrom records the version an in-panel self-update is replacing.
// Written immediately before the restart, so the binary that comes up can tell a
// self-update apart from any other restart and say what it upgraded from.
func (s *SettingService) SetPanelUpdatedFrom(version string) error {
	return s.setString("panelUpdatedFrom", version)
}

// TakePanelUpdatedFrom returns the version the last in-panel self-update replaced
// and clears the record, so the news is delivered exactly once.
//
// Reading and clearing are one operation on purpose: a plain getter would leave
// the flag set and re-announce the same update on every dashboard load until
// something else cleared it. Empty means no self-update is pending announcement,
// which is the state after any ordinary restart.
//
// Not atomic against a concurrent caller, and it does not need to be: the worst
// case is two browser tabs owned by the same super admin both showing the notice,
// and the route that reaches this is super-admin only.
func (s *SettingService) TakePanelUpdatedFrom() string {
	from, err := s.getString("panelUpdatedFrom")
	if err != nil || from == "" {
		return ""
	}
	if err := s.setString("panelUpdatedFrom", ""); err != nil {
		// Report it anyway: an undeliverable clear is a repeated notice, which is
		// better than swallowing the one the operator was waiting for.
		logger.Warning("panel update: clearing panelUpdatedFrom failed:", err)
	}
	return from
}

// provisionedNone is the sentinel written when the host is deliberately
// provisioned for NO cores (every core uninstalled).
//
// It exists because "" cannot mean two different things. The stored value
// defaults to "" for an install that predates per-core tracking, and that case
// is credited with provisionBaseline. Writing "" for "the operator removed
// everything" would collide with it and silently resurrect L2TP, PPTP, OpenVPN
// and OpenConnect as installed the moment the last core was removed.
const provisionedNone = "none"

// GetProvisionedProtocols returns the VPN cores the host is provisioned for, as
// recorded by SetProvisionedProtocols. Empty both when never recorded and when
// recorded as none; use HasRecordedProvisionedProtocols to tell those apart.
func (s *SettingService) GetProvisionedProtocols() []string {
	v, err := s.getString("provisionedProtocols")
	if err != nil || strings.TrimSpace(v) == provisionedNone {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// HasRecordedProvisionedProtocols reports whether this install has ever recorded
// its core set, that is, whether the empty result above means "none, and we know
// it" rather than "we have no idea".
func (s *SettingService) HasRecordedProvisionedProtocols() bool {
	v, err := s.getString("provisionedProtocols")
	return err == nil && strings.TrimSpace(v) != ""
}

// SetProvisionedProtocols records (comma-separated) the VPN cores the host is
// provisioned for. Called after a setup run and after an uninstall, so the two
// always agree on what is installed.
func (s *SettingService) SetProvisionedProtocols(list []string) error {
	joined := strings.Join(list, ",")
	if strings.TrimSpace(joined) == "" {
		joined = provisionedNone
	}
	return s.setString("provisionedProtocols", joined)
}

// GetSystemdServiceName returns the configured systemd unit name for the panel.
func (s *SettingService) GetSystemdServiceName() (string, error) {
	return s.getString("systemdServiceName")
}

// SetSystemdServiceName persists the systemd unit name for the panel.
func (s *SettingService) SetSystemdServiceName(value string) error {
	return s.setString("systemdServiceName", value)
}

// GetServerName returns the operator's own label for this server. Empty is the
// default and means the overview falls back to the host it was reached on.
//
// Deliberately NOT part of AllSetting: that struct is bound wholesale from the
// settings form, so a field the form does not post is written back as its zero
// value. A label edited from the overview would be wiped by the next unrelated
// save on the settings page.
func (s *SettingService) GetServerName() (string, error) {
	return s.getString("serverName")
}

// SetServerName persists the operator's label for this server. Empty clears it.
func (s *SettingService) SetServerName(value string) error {
	return s.setString("serverName", value)
}

// GetPublicIP returns the operator-pinned public IPv4 for this server. Empty is the
// default and means the panel falls back to live IP detection in the status probe.
func (s *SettingService) GetPublicIP() (string, error) {
	return s.getString("publicIp")
}

// SetPublicIP persists the operator-pinned public IPv4. Empty clears the override
// and restores automatic detection.
func (s *SettingService) SetPublicIP(value string) error {
	return s.setString("publicIp", value)
}

func (s *SettingService) GetTwoFactorToken() (string, error) {
	return s.getString("twoFactorToken")
}

func (s *SettingService) SetTwoFactorToken(value string) error {
	return s.setString("twoFactorToken", value)
}

func (s *SettingService) GetPort() (int, error) {
	return s.getInt("webPort")
}

func (s *SettingService) SetPort(port int) error {
	return s.setInt("webPort", port)
}

func (s *SettingService) SetCertFile(webCertFile string) error {
	return s.setString("webCertFile", webCertFile)
}

func (s *SettingService) GetCertFile() (string, error) {
	return s.getString("webCertFile")
}

func (s *SettingService) SetKeyFile(webKeyFile string) error {
	return s.setString("webKeyFile", webKeyFile)
}

func (s *SettingService) GetKeyFile() (string, error) {
	return s.getString("webKeyFile")
}

func (s *SettingService) GetExpireDiff() (int, error) {
	return s.getInt("expireDiff")
}

func (s *SettingService) GetTrafficDiff() (int, error) {
	return s.getInt("trafficDiff")
}

func (s *SettingService) GetSessionMaxAge() (int, error) {
	return s.getInt("sessionMaxAge")
}

func (s *SettingService) GetRemarkModel() (string, error) {
	return s.getString("remarkModel")
}

func (s *SettingService) GetSecret() ([]byte, error) {
	secret, err := s.getString("secret")
	return []byte(secret), err
}

func (s *SettingService) SetBasePath(basePath string) error {
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	return s.setString("webBasePath", basePath)
}

func (s *SettingService) GetBasePath() (string, error) {
	basePath, err := s.getString("webBasePath")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	return basePath, nil
}

func (s *SettingService) GetTimeLocation() (*time.Location, error) {
	l, err := s.getString("timeLocation")
	if err != nil {
		return nil, err
	}
	location, err := time.LoadLocation(l)
	if err != nil {
		defaultLocation := defaultValueMap["timeLocation"]
		logger.Errorf("location <%v> not exist, using default location: %v", l, defaultLocation)
		location, err = time.LoadLocation(defaultLocation)
		if err != nil {
			logger.Errorf("failed to load default location, using UTC: %v", err)
			return time.UTC, nil
		}
		return location, nil
	}
	return location, nil
}

func (s *SettingService) GetSubEnable() (bool, error) {
	return s.getBool("subEnable")
}

func (s *SettingService) GetSubJsonEnable() (bool, error) {
	return s.getBool("subJsonEnable")
}

func (s *SettingService) GetSubTitle() (string, error) {
	return s.getString("subTitle")
}

func (s *SettingService) GetSubSupportUrl() (string, error) {
	return s.getString("subSupportUrl")
}

func (s *SettingService) GetSubProfileUrl() (string, error) {
	return s.getString("subProfileUrl")
}

func (s *SettingService) GetSubAnnounce() (string, error) {
	return s.getString("subAnnounce")
}

func (s *SettingService) GetSubEnableRouting() (bool, error) {
	return s.getBool("subEnableRouting")
}

func (s *SettingService) GetSubRoutingRules() (string, error) {
	return s.getString("subRoutingRules")
}

func (s *SettingService) GetSubListen() (string, error) {
	return s.getString("subListen")
}

func (s *SettingService) GetSubPort() (int, error) {
	return s.getInt("subPort")
}

func (s *SettingService) GetSubPath() (string, error) {
	return s.getString("subPath")
}

func (s *SettingService) GetSubJsonPath() (string, error) {
	return s.getString("subJsonPath")
}

func (s *SettingService) GetSubDomain() (string, error) {
	return s.getString("subDomain")
}

func (s *SettingService) SetSubCertFile(subCertFile string) error {
	return s.setString("subCertFile", subCertFile)
}

func (s *SettingService) GetSubCertFile() (string, error) {
	return s.getString("subCertFile")
}

func (s *SettingService) SetSubKeyFile(subKeyFile string) error {
	return s.setString("subKeyFile", subKeyFile)
}

func (s *SettingService) GetSubKeyFile() (string, error) {
	return s.getString("subKeyFile")
}

func (s *SettingService) GetSubUpdates() (string, error) {
	return s.getString("subUpdates")
}

func (s *SettingService) GetSubEncrypt() (bool, error) {
	return s.getBool("subEncrypt")
}

func (s *SettingService) GetSubShowInfo() (bool, error) {
	return s.getBool("subShowInfo")
}

func (s *SettingService) GetPageSize() (int, error) {
	return s.getInt("pageSize")
}

func (s *SettingService) GetSubURI() (string, error) {
	return s.getString("subURI")
}

func (s *SettingService) GetSubJsonURI() (string, error) {
	return s.getString("subJsonURI")
}

func (s *SettingService) GetSubClashEnable() (bool, error) {
	return s.getBool("subClashEnable")
}

func (s *SettingService) GetSubClashPath() (string, error) {
	return s.getString("subClashPath")
}

func (s *SettingService) GetSubClashURI() (string, error) {
	return s.getString("subClashURI")
}

func (s *SettingService) GetSubJsonFragment() (string, error) {
	return s.getString("subJsonFragment")
}

func (s *SettingService) GetSubJsonNoises() (string, error) {
	return s.getString("subJsonNoises")
}

func (s *SettingService) GetSubJsonMux() (string, error) {
	return s.getString("subJsonMux")
}

func (s *SettingService) GetSubJsonRules() (string, error) {
	return s.getString("subJsonRules")
}

// GetSubTemplate returns which output format the raw subscription link serves:
// base64 (default), plain, clash, json or custom.
func (s *SettingService) GetSubTemplate() (string, error) {
	return s.getString("subTemplate")
}

// GetSubCustomTemplate returns the operator-authored template body used when
// subTemplate is "custom". Placeholders ($links, $email, ...) are expanded by the
// sub server per request.
func (s *SettingService) GetSubCustomTemplate() (string, error) {
	return s.getString("subCustomTemplate")
}

func (s *SettingService) GetDatepicker() (string, error) {
	return s.getString("datepicker")
}

func (s *SettingService) GetWarp() (string, error) {
	return s.getString("warp")
}

func (s *SettingService) SetWarp(data string) error {
	return s.setString("warp", data)
}

func (s *SettingService) GetNord() (string, error) {
	return s.getString("nord")
}

func (s *SettingService) SetNord(data string) error {
	return s.setString("nord", data)
}

func (s *SettingService) GetExternalTrafficInformEnable() (bool, error) {
	return s.getBool("externalTrafficInformEnable")
}

func (s *SettingService) SetExternalTrafficInformEnable(value bool) error {
	return s.setBool("externalTrafficInformEnable", value)
}

func (s *SettingService) GetExternalTrafficInformURI() (string, error) {
	return s.getString("externalTrafficInformURI")
}

func (s *SettingService) SetExternalTrafficInformURI(InformURI string) error {
	return s.setString("externalTrafficInformURI", InformURI)
}

// GetIpLimitEnable reports whether the panel offers the per-client IP Limit controls.
// Always true, and kept as a (bool, error) getter so its callers and the settings map
// that publishes "ipLimitEnable" to the UI are unchanged.
//
// It used to derive from the Xray access log path, back when the limit was enforced by
// scraping that log and handing the offending address to fail2ban. Since the shipped
// template sets "access": "none" (config.json), that made the entire IP Limit UI
// invisible on a default install: the feature was off unless an operator first turned on
// a log they had no reason to connect to it. Enforcement now happens inside the core,
// which reads each account's cap from the speedlimits.json sidecar and never looks at the
// access log, so there is nothing left to gate on. A client's own limit of 0 already
// means "no cap" for that client, which is the real off switch.
func (s *SettingService) GetIpLimitEnable() (bool, error) {
	return true, nil
}

// GetLdapEnable returns whether LDAP is enabled.
func (s *SettingService) GetLdapEnable() (bool, error) {
	return s.getBool("ldapEnable")
}

func (s *SettingService) GetLdapHost() (string, error) {
	return s.getString("ldapHost")
}

func (s *SettingService) GetLdapPort() (int, error) {
	return s.getInt("ldapPort")
}

func (s *SettingService) GetLdapUseTLS() (bool, error) {
	return s.getBool("ldapUseTLS")
}

func (s *SettingService) GetLdapBindDN() (string, error) {
	return s.getString("ldapBindDN")
}

func (s *SettingService) GetLdapPassword() (string, error) {
	return s.getString("ldapPassword")
}

func (s *SettingService) GetLdapBaseDN() (string, error) {
	return s.getString("ldapBaseDN")
}

func (s *SettingService) GetLdapUserFilter() (string, error) {
	return s.getString("ldapUserFilter")
}

func (s *SettingService) GetLdapUserAttr() (string, error) {
	return s.getString("ldapUserAttr")
}

func (s *SettingService) GetLdapVlessField() (string, error) {
	return s.getString("ldapVlessField")
}

func (s *SettingService) GetLdapSyncCron() (string, error) {
	return s.getString("ldapSyncCron")
}

func (s *SettingService) GetLdapFlagField() (string, error) {
	return s.getString("ldapFlagField")
}

func (s *SettingService) GetLdapTruthyValues() (string, error) {
	return s.getString("ldapTruthyValues")
}

func (s *SettingService) GetLdapInvertFlag() (bool, error) {
	return s.getBool("ldapInvertFlag")
}

func (s *SettingService) GetLdapInboundTags() (string, error) {
	return s.getString("ldapInboundTags")
}

func (s *SettingService) GetLdapAutoCreate() (bool, error) {
	return s.getBool("ldapAutoCreate")
}

func (s *SettingService) GetLdapAutoDelete() (bool, error) {
	return s.getBool("ldapAutoDelete")
}

func (s *SettingService) GetLdapDefaultTotalGB() (int, error) {
	return s.getInt("ldapDefaultTotalGB")
}

func (s *SettingService) GetLdapDefaultExpiryDays() (int, error) {
	return s.getInt("ldapDefaultExpiryDays")
}

func (s *SettingService) GetLdapDefaultLimitIP() (int, error) {
	return s.getInt("ldapDefaultLimitIP")
}

func (s *SettingService) GetRadiusSecret() (string, error) {
	return s.getString("radiusSecret")
}

func (s *SettingService) SetRadiusSecret(secret string) error {
	return s.setString("radiusSecret", secret)
}

func (s *SettingService) UpdateAllSetting(allSetting *entity.AllSetting) error {
	if err := allSetting.CheckValid(); err != nil {
		return err
	}

	v := reflect.ValueOf(allSetting).Elem()
	t := reflect.TypeFor[entity.AllSetting]()
	fields := reflect_util.GetFields(t)
	errs := make([]error, 0)
	for _, field := range fields {
		key := field.Tag.Get("json")
		fieldV := v.FieldByName(field.Name)
		value := fmt.Sprint(fieldV.Interface())
		err := s.saveSetting(key, value)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return common.Combine(errs...)
}

func (s *SettingService) GetDefaultXrayConfig() (any, error) {
	var jsonData any
	err := json.Unmarshal([]byte(xrayTemplateConfig), &jsonData)
	if err != nil {
		return nil, err
	}
	return jsonData, nil
}

func extractHostname(host string) string {
	h, _, err := net.SplitHostPort(host)
	// Err is not nil means host does not contain port
	if err != nil {
		h = host
	}

	ip := net.ParseIP(h)
	// If it's not an IP, return as is
	if ip == nil {
		return h
	}

	// If it's an IPv4, return as is
	if ip.To4() != nil {
		return h
	}

	// IPv6 needs bracketing
	return "[" + h + "]"
}

// panelSettingsOnlyDefaults are the GetDefaultSettings keys a caller without
// PermPanelSettings does not get. They are inbound-authoring inputs (the panel's
// TLS cert/key PATHS, pre-filled when an inbound enables TLS) and an admin who
// cannot reach Panel Settings cannot create inbounds either, so withholding them
// costs nothing and keeps filesystem paths out of a reseller's page source.
var panelSettingsOnlyDefaults = []string{"defaultCert", "defaultKey"}

// GetDefaultSettings returns the read-only defaults every client-rendering page
// needs: the expiry/traffic warning thresholds, the subscription URIs, the date
// picker locale, the page size, and the core-provisioning state.
//
// full=false trims panelSettingsOnlyDefaults for callers who hold no
// PermPanelSettings. It is NOT a permission check by itself: the route is what
// decides who may call this at all.
func (s *SettingService) GetDefaultSettings(host string, full bool) (map[string]any, error) {
	type settingFunc func() (any, error)
	settings := map[string]settingFunc{
		"expireDiff":     func() (any, error) { return s.GetExpireDiff() },
		"trafficDiff":    func() (any, error) { return s.GetTrafficDiff() },
		"pageSize":       func() (any, error) { return s.GetPageSize() },
		"defaultCert":    func() (any, error) { return s.GetCertFile() },
		"defaultKey":     func() (any, error) { return s.GetKeyFile() },
		"tgBotEnable":    func() (any, error) { return s.GetTgbotEnabled() },
		"subEnable":      func() (any, error) { return s.GetSubEnable() },
		"subJsonEnable":  func() (any, error) { return s.GetSubJsonEnable() },
		"subClashEnable": func() (any, error) { return s.GetSubClashEnable() },
		"subTitle":       func() (any, error) { return s.GetSubTitle() },
		"subURI":         func() (any, error) { return s.GetSubURI() },
		"subJsonURI":     func() (any, error) { return s.GetSubJsonURI() },
		"subClashURI":    func() (any, error) { return s.GetSubClashURI() },
		"remarkModel":    func() (any, error) { return s.GetRemarkModel() },
		"datepicker":     func() (any, error) { return s.GetDatepicker() },
		"ipLimitEnable":  func() (any, error) { return s.GetIpLimitEnable() },
		// The overview's access-log viewer reads Xray's access FILE, so this is what
		// decides whether it has anything to show. It used to ride on ipLimitEnable,
		// which meant the same thing until IP-limit enforcement moved into the core and
		// that getter became an unconditional true.
		"xrayAccessLogEnable": func() (any, error) { return xray.AccessLogEnabled(), nil },
		"provisioned":         func() (any, error) { var cs CoreService; return cs.IsProvisioned(), nil },
		"missingProtocols":    func() (any, error) { var cs CoreService; return cs.MissingProtocols(), nil },
	}

	result := make(map[string]any)

	for key, fn := range settings {
		value, err := fn()
		if err != nil {
			return nil, err
		}
		result[key] = value
	}

	subEnable := result["subEnable"].(bool)
	subJsonEnable := false
	if v, ok := result["subJsonEnable"]; ok {
		if b, ok2 := v.(bool); ok2 {
			subJsonEnable = b
		}
	}
	subClashEnable := false
	if v, ok := result["subClashEnable"]; ok {
		if b, ok2 := v.(bool); ok2 {
			subClashEnable = b
		}
	}
	if (subEnable && result["subURI"].(string) == "") || (subJsonEnable && result["subJsonURI"].(string) == "") || (subClashEnable && result["subClashURI"].(string) == "") {
		subURI := ""
		subTitle, _ := s.GetSubTitle()
		subPort, _ := s.GetSubPort()
		subPath, _ := s.GetSubPath()
		subJsonPath, _ := s.GetSubJsonPath()
		subClashPath, _ := s.GetSubClashPath()
		subDomain, _ := s.GetSubDomain()
		subKeyFile, _ := s.GetSubKeyFile()
		subCertFile, _ := s.GetSubCertFile()
		subTLS := false
		if subKeyFile != "" && subCertFile != "" {
			subTLS = true
		}
		if subDomain == "" {
			subDomain = extractHostname(host)
		}
		if subTLS {
			subURI = "https://"
		} else {
			subURI = "http://"
		}
		if (subPort == 443 && subTLS) || (subPort == 80 && !subTLS) {
			subURI += subDomain
		} else {
			subURI += fmt.Sprintf("%s:%d", subDomain, subPort)
		}
		if subEnable && result["subURI"].(string) == "" {
			result["subURI"] = subURI + subPath
		}
		if result["subTitle"].(string) == "" {
			result["subTitle"] = subTitle
		}
		if subJsonEnable && result["subJsonURI"].(string) == "" {
			result["subJsonURI"] = subURI + subJsonPath
		}
		if subClashEnable && result["subClashURI"].(string) == "" {
			result["subClashURI"] = subURI + subClashPath
		}
	}

	// Trimmed last, so the sub-URI synthesis above still runs off the full map.
	if !full {
		for _, k := range panelSettingsOnlyDefaults {
			delete(result, k)
		}
	}

	return result, nil
}
