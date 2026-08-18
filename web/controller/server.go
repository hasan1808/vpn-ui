package controller

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/web/global"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/web/session"
	"github.com/hasan1808/pro-ui/web/websocket"

	"github.com/gin-gonic/gin"
)

var filenameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-.]+$`)

// ServerController handles server management and status-related operations.
type ServerController struct {
	BaseController

	serverService  service.ServerService
	settingService service.SettingService
	inboundService service.InboundService

	lastStatus *service.Status

	lastVersions        []string
	lastGetVersionsTime int64 // unix seconds

	locMu            sync.Mutex // guards lastLocation/lastLocationTime
	lastLocation     *service.ExitInfo
	lastLocationTime int64 // unix seconds

	updMu               sync.Mutex // guards lastPanelUpdate/lastPanelUpdateTime
	lastPanelUpdate     *service.PanelUpdateInfo
	lastPanelUpdateTime int64 // unix seconds
}

// NewServerController creates a new ServerController, initializes routes, and starts background tasks.
func NewServerController(g *gin.RouterGroup) *ServerController {
	a := &ServerController{}
	a.initRouter(g)
	a.startTask()
	return a
}

// initRouter sets up the routes for server status, Xray management, and utility endpoints.
func (a *ServerController) initRouter(g *gin.RouterGroup) {

	g.GET("/status", a.status)
	g.GET("/userStats", a.userStats)
	g.GET("/serverName", a.getServerName)
	g.GET("/panelLocation", a.panelLocation)
	g.GET("/cpuHistory/:bucket", a.getCpuHistoryBucket)
	g.GET("/getXrayVersion", a.getXrayVersion)
	// Escalation-class, and DELEGABLE since 2026-07-31: these answer to
	// PermOverviewManage (requireOverviewManage, which also resolves a reseller's
	// profile columns) rather than to the super admin role.
	//
	// They are still escalation-class. getConfigJson and getDb expose every admin's
	// data and getDb carries the users table with its bcrypt hashes; importDB replaces
	// the database wholesale; updatePanel swaps the running binary as root. Anyone
	// holding that bit can therefore take the panel, which the operator chose
	// deliberately with the consequence stated. Do not "tidy" this back to
	// requireSuperAdmin, and do not widen the bit's reach any further without asking:
	// the line drawn was "everything the overview offers", which is why admin
	// management, the host reboot, core uninstall and the systemd unit stayed behind
	// requireSuperAdmin. See overviewManage in permission.go.
	g.GET("/getConfigJson", requireOverviewManage(), a.getConfigJson)
	g.GET("/getDb", requireOverviewManage(), a.getDb)
	g.GET("/getNewUUID", a.getNewUUID)
	g.GET("/getNewX25519Cert", a.getNewX25519Cert)
	g.GET("/getNewmldsa65", a.getNewmldsa65)
	g.GET("/getNewmlkem768", a.getNewmlkem768)
	g.GET("/getNewVlessEnc", a.getNewVlessEnc)
	g.GET("/distroStatus", a.distroStatus)
	g.GET("/geofileStatus", a.geofileStatus)
	// The in-flight geofile download, so an overview that was reopened mid-transfer
	// can re-attach instead of looking idle. Read-only, like geofileStatus beside it.
	g.GET("/geofileProgress", a.geofileProgress)
	g.GET("/checkUpdate", a.checkUpdate)
	g.GET("/updateProgress", a.updateProgress)
	// Reports (once) that the panel came back from a self-update. Gated to match
	// updatePanel: reading it CLEARS it, so an admin without the bit loading the
	// dashboard first would otherwise consume the notice meant for whoever ran the
	// update.
	g.GET("/updateResult", requireOverviewManage(), a.updateResult)

	// Renaming the server relabels the panel for every admin. Offered only from the
	// overview, so it answers to the bit that says this overview may act. Reading it
	// stays open: the overview shows the label to anyone who may open the page.
	//
	// This used to AND the panel-settings bit on top. That is gone deliberately: the
	// AND made the grant unreachable for a reseller, whose derived mask never carries
	// a settings bit, so their AllowOverviewManage column could never do anything.
	g.POST("/serverName", requireOverviewManage(), a.setServerName)

	// Panel-wide effects rather than per-inbound, so they follow the Xray permission.
	g.POST("/stopXrayService", requirePerm(model.PermXraySettings), a.stopXrayService)
	g.POST("/updatePanel", requireOverviewManage(), a.updatePanel)
	g.POST("/cancelUpdate", requireOverviewManage(), a.cancelUpdate)
	// Manual update: a binary the operator names, either uploaded from their machine
	// or downloaded by the panel from a URL they give. Same escalation class as
	// updatePanel, since both end in the same binary swap. Split in two so the
	// operator confirms against a version the server read out of the file itself,
	// not against its name or its address.
	g.POST("/uploadPanelBinary", requireOverviewManage(), a.uploadPanelBinary)
	g.POST("/fetchPanelBinary", requireOverviewManage(), a.fetchPanelBinary)
	g.POST("/applyPanelBinary", requireOverviewManage(), a.applyPanelBinary)
	g.POST("/discardPanelBinary", requireOverviewManage(), a.discardPanelBinary)
	g.POST("/restartXrayService", requirePerm(model.PermXraySettings), a.restartXrayService)
	g.POST("/installXray/:version", requirePerm(model.PermXraySettings), a.installXray)
	// Geofile updates are reached only from the overview's geofiles dialog, so they
	// answer to the overview's acting bit alone, for the same reason serverName does.
	// stopXrayService and restartXrayService above deliberately do NOT: those are also
	// driven from the Xray settings page, where this bit has no business being
	// consulted, and where the Xray permission is the right question.
	g.POST("/updateGeofile", requireOverviewManage(), a.updateGeofile)
	g.POST("/updateGeofile/:fileName", requireOverviewManage(), a.updateGeofile)
	// Whether the panel refreshes the geo data on its own. Same dialog, same bit.
	g.POST("/geofileAutoUpdate", requireOverviewManage(), a.setGeofileAutoUpdate)
	// Panel and Xray logs name other admins' inbounds, clients and IPs.
	g.POST("/logs/:count", requireOverviewManage(), a.getLogs)
	g.POST("/xraylogs/:count", requireOverviewManage(), a.getXrayLogs)
	g.POST("/importDB", requireOverviewManage(), a.importDB)
	g.POST("/importForeignDB", requireOverviewManage(), a.importForeignDB)
	g.POST("/getNewEchCert", a.getNewEchCert)
}

// refreshStatus updates the cached server status and collects CPU history.
func (a *ServerController) refreshStatus() {
	a.lastStatus = a.serverService.GetStatus(a.lastStatus)
	// collect cpu history when status is fresh
	if a.lastStatus != nil {
		a.serverService.AppendCpuSample(time.Now(), a.lastStatus.Cpu)
		// Broadcast status update via WebSocket
		websocket.BroadcastStatus(a.lastStatus)
	}
}

// startTask initiates background tasks for continuous status monitoring.
func (a *ServerController) startTask() {
	webServer := global.GetWebServer()
	c := webServer.GetCron()
	c.AddFunc("@every 2s", func() {
		// Always refresh to keep CPU history collected continuously.
		// Sampling is lightweight and capped to ~6 hours in memory.
		a.refreshStatus()
	})
}

// status returns the current server status information.
func (a *ServerController) status(c *gin.Context) { jsonObj(c, a.lastStatus, nil) }

// userStats returns the overview's account roll-up (total, online, depleted and
// expiring) for the logged-in admin. The inbounds page derives the same four
// numbers in the browser from the full inbound list; the overview wants only the
// counts, so it gets them without shipping every client.
func (a *ServerController) userStats(c *gin.Context) {
	stats, err := a.inboundService.GetClientStatsFor(session.GetLoginUser(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.obtain"), err)
		return
	}
	jsonObj(c, stats, nil)
}

// getServerName returns the operator's label for this server, empty when unset.
func (a *ServerController) getServerName(c *gin.Context) {
	name, err := a.settingService.GetServerName()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, gin.H{"serverName": name}, nil)
}

// setServerName persists the operator's label for this server. Posting an empty
// value clears it and returns the overview to the host name.
func (a *ServerController) setServerName(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("serverName"))
	if len([]rune(name)) > 64 {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"),
			errors.New("server name is limited to 64 characters"))
		return
	}
	err := a.settingService.SetServerName(name)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

// panelLocation reports where the panel's own traffic egresses, for the
// overview's "Panel Location" row.
//
// Checked when the overview opens rather than once per process: a panel started
// by systemd at boot often runs before the network settles, and a once-only
// lookup would leave the row permanently blank until a restart. A public IP can
// also simply change under the panel.
//
// Cached for 5 minutes, INCLUDING failures, exactly like checkUpdate: the probe
// is an outbound request and reloading the overview must not be able to hammer
// it. ?force=1 bypasses the cache.
//
// Always returns success with a `found` flag rather than an error, so a host
// that cannot reach the probe renders "error getting location info" instead of
// raising a toast on every dashboard visit.
func (a *ServerController) panelLocation(c *gin.Context) {
	now := time.Now().Unix()
	force := c.Query("force") != ""

	a.locMu.Lock()
	if !force && a.lastLocation != nil && now-a.lastLocationTime <= 300 {
		cached := a.lastLocation
		a.locMu.Unlock()
		jsonObj(c, locationPayload(cached), nil)
		return
	}
	a.locMu.Unlock()

	info := service.LookupPanelExit()

	a.locMu.Lock()
	a.lastLocationTime = now
	// A failed lookup is cached too, so a censored host is probed at most once
	// per 5 minutes instead of on every overview load.
	a.lastLocation = &info
	a.locMu.Unlock()

	jsonObj(c, locationPayload(&info), nil)
}

// locationPayload adds the found flag the UI branches on: it distinguishes
// "looked and could not tell" from "not looked yet", which is what lets the row
// show an error rather than silently staying hidden.
func locationPayload(info *service.ExitInfo) gin.H {
	return gin.H{
		"found":       info != nil && !info.Empty(),
		"ipv4":        info.IPv4,
		"ipv6":        info.IPv6,
		"countryCode": info.CountryCode,
	}
}

// distroStatus reports whether the running host distro is on vpn-ui's tested list,
// for the dashboard's unsupported-distro warning modal.
func (a *ServerController) distroStatus(c *gin.Context) {
	supported, pretty, reason := service.DistroSupported()
	jsonObj(c, gin.H{
		"supported": supported,
		"pretty":    pretty,
		"reason":    reason,
		"tested":    service.SupportedDistroSummary(),
	}, nil)
}

// getCpuHistoryBucket retrieves aggregated CPU usage history based on the specified time bucket.
func (a *ServerController) getCpuHistoryBucket(c *gin.Context) {
	bucketStr := c.Param("bucket")
	bucket, err := strconv.Atoi(bucketStr)
	if err != nil || bucket <= 0 {
		jsonMsg(c, "invalid bucket", fmt.Errorf("bad bucket"))
		return
	}
	allowed := map[int]bool{
		2:   true, // Real-time view
		30:  true, // 30s intervals
		60:  true, // 1m intervals
		120: true, // 2m intervals
		180: true, // 3m intervals
		300: true, // 5m intervals
	}
	if !allowed[bucket] {
		jsonMsg(c, "invalid bucket", fmt.Errorf("unsupported bucket"))
		return
	}
	points := a.serverService.AggregateCpuHistory(bucket, 60)
	jsonObj(c, points, nil)
}

// getXrayVersion retrieves available Xray versions, with caching for 1 minute.
func (a *ServerController) getXrayVersion(c *gin.Context) {
	now := time.Now().Unix()
	if now-a.lastGetVersionsTime <= 60 { // 1 minute cache
		jsonObj(c, a.lastVersions, nil)
		return
	}

	versions, err := a.serverService.GetXrayVersions()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "getVersion"), err)
		return
	}

	a.lastVersions = versions
	a.lastGetVersionsTime = now

	jsonObj(c, versions, nil)
}

// checkUpdate reports whether a newer vpn-ui panel release is available. The
// result is cached for 5 minutes — including FAILURES (negative cache) — so the
// per-overview-load auto-check can't burn GitHub's unauthenticated rate limit even
// during an outage. The manual button passes ?force=1 to bypass the cache.
//
// The auto-check (non-force) must stay SILENT: on error it returns via jsonObj with
// an empty message, so HttpUtil raises no toast. Only a manual check surfaces the
// error (a toast on an explicit click is expected).
func (a *ServerController) checkUpdate(c *gin.Context) {
	now := time.Now().Unix()
	force := c.Query("force") != ""

	a.updMu.Lock()
	if !force && a.lastPanelUpdate != nil && now-a.lastPanelUpdateTime <= 300 {
		cached := a.lastPanelUpdate
		a.updMu.Unlock()
		jsonObj(c, cached, nil)
		return
	}
	a.updMu.Unlock()

	info, err := a.serverService.CheckPanelUpdate()

	a.updMu.Lock()
	a.lastPanelUpdateTime = now // cache success AND failure to bound GitHub calls
	if err == nil {
		a.lastPanelUpdate = info
	} else if a.lastPanelUpdate == nil {
		// Cold start with GitHub failing: seed the benign result (info is non-nil,
		// Available=false) so the cache-hit guard engages and we stop re-hitting
		// GitHub every load. Never overwrite a prior real result with this.
		a.lastPanelUpdate = info
	}
	last := a.lastPanelUpdate
	a.updMu.Unlock()

	if err != nil {
		if force {
			jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err) // manual: surface it
			return
		}
		// auto check: stay silent (empty msg => no toast). Prefer last-known-good.
		if last != nil {
			jsonObj(c, last, nil)
		} else {
			jsonObj(c, info, nil) // benign: Available=false
		}
		return
	}
	jsonObj(c, info, nil)
}

// updatePanel downloads the latest release, replaces the running binary, and
// restarts the panel. The response returns before the restart fires. On success it
// returns an empty message (no toast) — the frontend shows the "restarting" alert;
// only failures toast.
func (a *ServerController) updatePanel(c *gin.Context) {
	err := a.serverService.UpdatePanel()
	if errors.Is(err, service.ErrPanelUpdateCancelled) {
		// The user asked for this, so it isn't a failure: report success and let the
		// frontend reset on the "cancelled" flag instead of toasting an error.
		jsonObj(c, gin.H{"cancelled": true}, nil)
		return
	}
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err)
		return
	}
	jsonObj(c, nil, nil)
}

// uploadPanelBinary receives a binary the operator picked in the browser, stages it
// beside the running one and answers with the versions, so the confirmation names
// what the server actually read rather than what the file was called.
//
// multipart/form-data, unlike every other POST in this panel: a file cannot travel
// through the form-urlencoded body axios builds for the rest of the API.
//
// It reads the part with c.Request.MultipartReader() rather than c.FormFile. FormFile
// calls ParseMultipartForm, which buffers MaxMultipartMemory in RAM and spills the
// rest into os.TempDir, which is tmpfs (RAM) on several of the distros this panel
// targets. The release asset is around 315MB, so on a small VPS that path would
// exhaust memory before the file ever reached its destination, and then copy it a
// second time. MultipartReader streams straight to the staging file at constant
// memory. Nothing may touch c.PostForm, c.FormFile or ParseForm before it, or the
// body is already consumed.
func (a *ServerController) uploadPanelBinary(c *gin.Context) {
	// The hard cap, and the only one that survives a client that lies about its length
	// or sends no length at all.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, service.MaxPanelUploadSize)

	mr, err := c.Request.MultipartReader()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err)
		return
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err)
			return
		}
		if part.FormName() != "binary" {
			_ = part.Close()
			continue
		}
		info, err := service.StagePanelBinary(part, c.Request.ContentLength)
		_ = part.Close()
		if err != nil {
			jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err)
			return
		}
		jsonObj(c, info, nil)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), errors.New("no binary was uploaded"))
}

// fetchPanelBinary downloads a binary from an operator-supplied URL and stages it, so
// the confirmation modal and applyPanelBinary below serve both manual sources. The
// answer is the same StagedPanelInfo an upload produces, read out of the downloaded
// file rather than out of the address, because an address proves nothing about what is
// at the other end of it.
//
// This one may block for a long time (the asset is around 315MB and the point of the
// feature is a box on a slow or restricted link), so the service bounds it rather than
// leaving it to the client giving up.
func (a *ServerController) fetchPanelBinary(c *gin.Context) {
	info, err := service.StagePanelBinaryFromURL(c.PostForm("url"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err)
		return
	}
	jsonObj(c, info, nil)
}

// applyPanelBinary installs the staged upload and restarts the panel. Like
// updatePanel it answers before the restart lands, and says nothing on success so the
// frontend's own "restarting" state is what the operator sees.
//
// Ordinary form-urlencoded: only the token travels here, the bytes arrived at
// uploadPanelBinary.
func (a *ServerController) applyPanelBinary(c *gin.Context) {
	if err := service.ApplyStagedPanelBinary(c.PostForm("token")); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err)
		return
	}
	jsonObj(c, nil, nil)
}

// discardPanelBinary drops a staged upload the operator decided not to install, so a
// binary they backed away from is not left sitting next to the running one.
func (a *ServerController) discardPanelBinary(c *gin.Context) {
	service.DiscardStagedPanelBinary()
	jsonObj(c, nil, nil)
}

// cancelUpdate aborts an in-flight update download. Refused once the update reaches
// the install phase, which must not be interrupted.
func (a *ServerController) cancelUpdate(c *gin.Context) {
	if err := a.serverService.CancelPanelUpdate(); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.updateCancel"), err)
		return
	}
	jsonObj(c, nil, nil)
}

// updateProgress reports the in-flight self-update's phase, download percent and
// byte counters, polled by the overview to render the progress bar + speed meter.
func (a *ServerController) updateProgress(c *gin.Context) {
	jsonObj(c, a.serverService.PanelUpdateProgress(), nil)
}

// updateResult reports whether this panel process is the one that came up after
// an in-panel self-update, and what version it replaced. Reading CONSUMES the
// record, so the overview announces a given update exactly once however many
// times it is reloaded afterwards.
//
// `updated` false is the ordinary answer: any restart that was not a self-update
// leaves nothing to report.
func (a *ServerController) updateResult(c *gin.Context) {
	jsonObj(c, a.serverService.TakePanelUpdateResult(), nil)
}

// installXray installs or updates Xray to the specified version.
func (a *ServerController) installXray(c *gin.Context) {
	version := c.Param("version")
	err := a.serverService.UpdateXray(version)
	jsonMsg(c, I18nWeb(c, "pages.index.xraySwitchVersionPopover"), err)
}

// geofileStatus reports which geo files are actually installed under bin/. Only
// two of the six the panel offers ship with the binary; the rest exist after a
// download and not before, and a routing rule that names one that is not there
// stops the core from starting at all.
func (a *ServerController) geofileStatus(c *gin.Context) {
	jsonObj(c, a.serverService.GetGeofileStatus(), nil)
}

// updateGeofile updates the specified geo file for Xray.
func (a *ServerController) updateGeofile(c *gin.Context) {
	fileName := c.Param("fileName")

	// Validate the filename for security (prevent path traversal attacks)
	if fileName != "" && !a.serverService.IsValidGeofileName(fileName) {
		jsonMsg(c, I18nWeb(c, "pages.index.geofileUpdatePopover"),
			fmt.Errorf("invalid filename: contains unsafe characters or path traversal patterns"))
		return
	}

	err := a.serverService.UpdateGeofile(fileName)
	jsonMsg(c, I18nWeb(c, "pages.index.geofileUpdatePopover"), err)
}

// geofileProgress reports the in-flight (or last finished) geofile update.
//
// updateGeofile blocks, but Gin does not kill a handler when the browser leaves,
// so navigating away abandons the response while the transfer carries on. This is
// how the overview finds that transfer again when it comes back.
func (a *ServerController) geofileProgress(c *gin.Context) {
	jsonObj(c, a.serverService.GeofileRunState(), nil)
}

// setGeofileAutoUpdate turns the periodic geo data refresh on or off.
func (a *ServerController) setGeofileAutoUpdate(c *gin.Context) {
	enabled := c.PostForm("enabled") == "true"
	err := a.settingService.SetGeofileAutoUpdate(enabled)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

// stopXrayService stops the Xray service.
func (a *ServerController) stopXrayService(c *gin.Context) {
	err := a.serverService.StopXrayService()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.xray.stopError"), err)
		websocket.BroadcastXrayState("error", err.Error())
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.xray.stopSuccess"), err)
	websocket.BroadcastXrayState("stop", "")
	websocket.BroadcastNotification(
		I18nWeb(c, "pages.xray.stopSuccess"),
		"Xray service has been stopped",
		"warning",
	)
}

// restartXrayService restarts the Xray service.
func (a *ServerController) restartXrayService(c *gin.Context) {
	err := a.serverService.RestartXrayService()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.xray.restartError"), err)
		websocket.BroadcastXrayState("error", err.Error())
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.xray.restartSuccess"), err)
	websocket.BroadcastXrayState("running", "")
	websocket.BroadcastNotification(
		I18nWeb(c, "pages.xray.restartSuccess"),
		"Xray service has been restarted successfully",
		"success",
	)
}

// getLogs retrieves the application logs based on count, level, and syslog filters.
func (a *ServerController) getLogs(c *gin.Context) {
	count := c.Param("count")
	level := c.PostForm("level")
	syslog := c.PostForm("syslog")
	logs := a.serverService.GetLogs(count, level, syslog)
	jsonObj(c, logs, nil)
}

// getXrayLogs retrieves Xray logs with filtering options for direct, blocked, and proxy traffic.
func (a *ServerController) getXrayLogs(c *gin.Context) {
	count := c.Param("count")
	filter := c.PostForm("filter")
	showDirect := c.PostForm("showDirect")
	showBlocked := c.PostForm("showBlocked")
	showProxy := c.PostForm("showProxy")

	var freedoms []string
	var blackholes []string

	//getting tags for freedom and blackhole outbounds
	config, err := a.settingService.GetDefaultXrayConfig()
	if err == nil && config != nil {
		if cfgMap, ok := config.(map[string]any); ok {
			if outbounds, ok := cfgMap["outbounds"].([]any); ok {
				for _, outbound := range outbounds {
					if obMap, ok := outbound.(map[string]any); ok {
						switch obMap["protocol"] {
						case "freedom":
							if tag, ok := obMap["tag"].(string); ok {
								freedoms = append(freedoms, tag)
							}
						case "blackhole":
							if tag, ok := obMap["tag"].(string); ok {
								blackholes = append(blackholes, tag)
							}
						}
					}
				}
			}
		}
	}

	if len(freedoms) == 0 {
		freedoms = []string{"direct"}
	}
	if len(blackholes) == 0 {
		blackholes = []string{"blocked"}
	}

	logs := a.serverService.GetXrayLogs(count, filter, showDirect, showBlocked, showProxy, freedoms, blackholes)
	jsonObj(c, logs, nil)
}

// getConfigJson retrieves the Xray configuration as JSON.
func (a *ServerController) getConfigJson(c *gin.Context) {
	configJson, err := a.serverService.GetConfigJson()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.getConfigError"), err)
		return
	}
	jsonObj(c, configJson, nil)
}

// getDb downloads the database file.
//
// The name is decided here and not in the browser: the overview reaches this with a
// plain navigation rather than an XHR, so Content-Disposition is the only place a
// filename can come from, and the picker's choices have to travel as query params.
func (a *ServerController) getDb(c *gin.Context) {
	db, err := a.serverService.GetDb()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.getDatabaseError"), err)
		return
	}

	// Still gated below: the builder sanitizes every component it assembles, but this
	// endpoint's guarantee is the gate, not the caller's good manners.
	filename := a.serverService.BuildBackupFilename(backupNameOptions(c), browserHost(c))

	if !isValidFilename(filename) {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("invalid filename"))
		return
	}

	// Set the headers for the response
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename="+filename)

	// Write the file contents to the response
	c.Writer.Write(db)
}

// backupNameOptions reads the filename picker's four checkboxes off the query
// string.
//
// A request carrying NONE of them is not "the operator unticked everything", it is
// an old bookmark, a script, or someone hitting /getDb directly, and those keep the
// dated name this endpoint has always produced. The picker posts all four every
// time, unticked ones included as false, so an all-false request is unambiguous and
// does yield the bare vpn-ui.db it asked for.
func backupNameOptions(c *gin.Context) service.BackupNameOptions {
	picked := false
	flag := func(name string) bool {
		value, present := c.GetQuery(name)
		picked = picked || present
		return value == "true"
	}

	opts := service.BackupNameOptions{
		Date:      flag("date"),
		Time:      flag("time"),
		PanelName: flag("panelName"),
		Domain:    flag("domain"),
	}
	if !picked {
		return service.BackupNameOptions{Date: true, Time: true}
	}
	return opts
}

func isValidFilename(filename string) bool {
	// Validate that the filename only contains allowed characters
	return filenameRegex.MatchString(filename)
}

// importDB imports a database file and restarts the Xray service.
func (a *ServerController) importDB(c *gin.Context) {
	// Get the file from the request body
	file, _, err := c.Request.FormFile("db")
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.readDatabaseError"), err)
		return
	}
	defer file.Close()
	// Always restart Xray before return
	defer a.serverService.RestartXrayService()
	// lastGetStatusTime removed; no longer needed
	// Import it
	err = a.serverService.ImportDB(file)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.importDatabaseError"), err)
		return
	}
	jsonObj(c, I18nWeb(c, "pages.index.importDatabaseSuccess"), nil)
}

// importForeignDB imports a stock 3x-ui (or vpn-ui) backup over the current
// database, keeping this panel's own reachability/identity settings. Unlike
// importDB (a like-for-like restore of this panel's own backup) it is meant for
// migrating in from another panel: it reports what landed, and because the admin
// accounts come from the backup, the operator signs in afterwards with the
// imported panel's login. activate=true regenerates daemon configs + restarts Xray.
func (a *ServerController) importForeignDB(c *gin.Context) {
	file, _, err := c.Request.FormFile("db")
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.readDatabaseError"), err)
		return
	}
	defer file.Close()
	report, err := a.serverService.ImportForeignDB(file, true)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.importDatabaseError"), err)
		return
	}
	jsonObj(c, report, nil)
}

// getNewX25519Cert generates a new X25519 certificate.
func (a *ServerController) getNewX25519Cert(c *gin.Context) {
	cert, err := a.serverService.GetNewX25519Cert()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewX25519CertError"), err)
		return
	}
	jsonObj(c, cert, nil)
}

// getNewmldsa65 generates a new ML-DSA-65 key.
func (a *ServerController) getNewmldsa65(c *gin.Context) {
	cert, err := a.serverService.GetNewmldsa65()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewmldsa65Error"), err)
		return
	}
	jsonObj(c, cert, nil)
}

// getNewEchCert generates a new ECH certificate for the given SNI.
func (a *ServerController) getNewEchCert(c *gin.Context) {
	sni := c.PostForm("sni")
	cert, err := a.serverService.GetNewEchCert(sni)
	if err != nil {
		jsonMsg(c, "get ech certificate", err)
		return
	}
	jsonObj(c, cert, nil)
}

// getNewVlessEnc generates a new VLESS encryption key.
func (a *ServerController) getNewVlessEnc(c *gin.Context) {
	out, err := a.serverService.GetNewVlessEnc()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewVlessEncError"), err)
		return
	}
	jsonObj(c, out, nil)
}

// getNewUUID generates a new UUID.
func (a *ServerController) getNewUUID(c *gin.Context) {
	uuidResp, err := a.serverService.GetNewUUID()
	if err != nil {
		jsonMsg(c, "Failed to generate UUID", err)
		return
	}

	jsonObj(c, uuidResp, nil)
}

// getNewmlkem768 generates a new ML-KEM-768 key.
func (a *ServerController) getNewmlkem768(c *gin.Context) {
	out, err := a.serverService.GetNewmlkem768()
	if err != nil {
		jsonMsg(c, "Failed to generate mlkem768 keys", err)
		return
	}
	jsonObj(c, out, nil)
}
