package controller

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/web/service"

	"github.com/gin-gonic/gin"
)

// XraySettingController handles Xray configuration and settings operations.
type XraySettingController struct {
	XraySettingService service.XraySettingService
	SettingService     service.SettingService
	InboundService     service.InboundService
	OutboundService    service.OutboundService
	XrayService        service.XrayService
	WarpService        service.WarpService
	NordService        service.NordService
	SshOutboundService service.SshOutboundService
	VpnOutboundService service.VpnOutboundService
}

// NewXraySettingController creates a new XraySettingController and initializes its routes.
func NewXraySettingController(g *gin.RouterGroup) *XraySettingController {
	a := &XraySettingController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for Xray settings management.
func (a *XraySettingController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/xray")
	g.Use(requirePerm(model.PermXraySettings))
	g.GET("/getDefaultJsonConfig", a.getDefaultXrayConfig)
	g.GET("/getOutboundsTraffic", a.getOutboundsTraffic)
	g.GET("/getXrayResult", a.getXrayResult)

	g.POST("/", a.getXraySetting)
	g.POST("/warp/:action", a.warp)
	g.POST("/warpsocks/:action", a.warpsocks)
	g.POST("/sshoutbound/:action", a.sshoutbound)
	g.POST("/vpnoutbound/:action", a.vpnoutbound)
	g.POST("/nord/:action", a.nord)
	g.POST("/update", a.updateSetting)
	g.POST("/resetOutboundsTraffic", a.resetOutboundsTraffic)
	g.POST("/testOutbound", a.testOutbound)
}

// getXraySetting retrieves the Xray configuration template, inbound tags, and outbound test URL.
func (a *XraySettingController) getXraySetting(c *gin.Context) {
	xraySetting, err := a.SettingService.GetXrayConfigTemplate()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	// Older versions of this handler embedded the raw DB value as
	// `xraySetting` in the response without checking if the value
	// already had that wrapper shape. When the frontend saved it
	// back through the textarea verbatim, the wrapper got persisted
	// and every subsequent save nested another layer, which is what
	// eventually produced the blank Xray Settings page in #4059.
	// Strip any such wrapper here, and heal the DB if we found one so
	// the next read is O(1) instead of climbing the same pile again.
	if unwrapped := service.UnwrapXrayTemplateConfig(xraySetting); unwrapped != xraySetting {
		if saveErr := a.XraySettingService.RepairXrayTemplate(unwrapped); saveErr == nil {
			xraySetting = unwrapped
		} else {
			// Don't fail the read — just serve the unwrapped value
			// and leave the DB healing for a later save.
			xraySetting = unwrapped
		}
	}
	inboundTags, err := a.InboundService.GetInboundTags()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	outboundTestUrl, _ := a.SettingService.GetXrayOutboundTestUrl()
	if outboundTestUrl == "" {
		outboundTestUrl = "https://www.google.com/generate_204"
	}
	xrayResponse := map[string]interface{}{
		"xraySetting":     json.RawMessage(xraySetting),
		"inboundTags":     json.RawMessage(inboundTags),
		"outboundTestUrl": outboundTestUrl,
	}
	result, err := json.Marshal(xrayResponse)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, string(result), nil)
}

// updateSetting updates the Xray configuration settings.
func (a *XraySettingController) updateSetting(c *gin.Context) {
	xraySetting := c.PostForm("xraySetting")
	if err := a.XraySettingService.SaveXraySetting(xraySetting); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
		return
	}
	outboundTestUrl := c.PostForm("outboundTestUrl")
	if outboundTestUrl == "" {
		outboundTestUrl = "https://www.google.com/generate_204"
	}
	_ = a.SettingService.SetXrayOutboundTestUrl(outboundTestUrl)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), nil)
}

// getDefaultXrayConfig retrieves the default Xray configuration.
func (a *XraySettingController) getDefaultXrayConfig(c *gin.Context) {
	defaultJsonConfig, err := a.SettingService.GetDefaultXrayConfig()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, defaultJsonConfig, nil)
}

// getXrayResult retrieves the current Xray service result.
func (a *XraySettingController) getXrayResult(c *gin.Context) {
	jsonObj(c, a.XrayService.GetXrayResult(), nil)
}

// warp handles Warp-related operations based on the action parameter.
func (a *XraySettingController) warp(c *gin.Context) {
	action := c.Param("action")
	var resp string
	var err error
	switch action {
	case "data":
		resp, err = a.WarpService.GetWarpData()
	case "del":
		err = a.WarpService.DelWarpData()
	case "config":
		resp, err = a.WarpService.GetWarpConfig()
	case "reg":
		skey := c.PostForm("privateKey")
		pkey := c.PostForm("publicKey")
		resp, err = a.WarpService.RegWarp(skey, pkey)
	case "license":
		license := c.PostForm("license")
		resp, err = a.WarpService.SetWarpLicense(license)
	}

	jsonObj(c, resp, err)
}

// warpsocks drives the "official WARP-CLI" SOCKS5 background lifecycle. install
// and uninstall kick off a non-blocking run and return the initial run state;
// the modal then polls "state" (~1s) for the live log. "installed" reports
// whether warp-cli is already present so the modal can offer Reinstall/Uninstall.
func (a *XraySettingController) warpsocks(c *gin.Context) {
	action := c.Param("action")
	switch action {
	case "install":
		port, _ := strconv.Atoi(c.PostForm("port"))
		service.StartWarpSocks("reinstall", port)
		jsonObj(c, service.WarpSocksState(), nil)
	case "uninstall":
		service.StartWarpSocks("uninstall", 0)
		jsonObj(c, service.WarpSocksState(), nil)
	case "state":
		jsonObj(c, service.WarpSocksState(), nil)
	case "installed":
		jsonObj(c, gin.H{"installed": service.WarpSocksInstalled()}, nil)
	default:
		jsonObj(c, service.WarpSocksState(), nil)
	}
}

// sshoutbound drives operator-configured SSH egress tunnels (list/save/delete/status).
// Each tunnel is backed by a synthesized tagged `socks` outbound the operator adds to the
// template, so it is reverse/routing-selectable purely by that tag. Form-urlencoded, per
// the panel convention (no JSON binding).
func (a *XraySettingController) sshoutbound(c *gin.Context) {
	switch c.Param("action") {
	case "list":
		jsonObj(c, a.SshOutboundService.List(), nil)
	case "save":
		var cfg service.SshOutboundConfig
		if err := c.ShouldBind(&cfg); err != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
			return
		}
		saved, err := a.SshOutboundService.Save(cfg)
		if err != nil {
			jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
			return
		}
		// The allocated loopback port goes back to the caller: it is what the
		// synthesized socks outbound has to point at, and only the server knows it.
		jsonObj(c, gin.H{"socksPort": saved.SocksPort}, nil)
	case "delete":
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), a.SshOutboundService.Delete(c.PostForm("tag")))
	case "status":
		up, log := a.SshOutboundService.Status(c.PostForm("tag"))
		jsonObj(c, gin.H{"running": up, "log": log}, nil)
	default:
		jsonObj(c, a.SshOutboundService.List(), nil)
	}
}

// vpnOutboundForm carries one client tunnel over the panel's form-urlencoded POSTs.
//
// It exists only because Settings cannot be bound directly. On the config it is a
// json.RawMessage, i.e. a byte slice, and gin's form binder walks a slice element by
// element through ParseUint: a JSON object in that field fails the whole bind with
// "strconv.ParseUint: invalid syntax", and an EMPTY field binds to a one-byte \x00
// blob that is not valid JSON either and would poison the stored list. So the nested
// blob travels as text and is unmarshalled by hand, the same way importInbound and
// testOutbound take theirs.
type vpnOutboundForm struct {
	Tag    string `form:"tag"`
	Kind   string `form:"kind"`
	Remark string `form:"remark"`
	Enable bool   `form:"enable"`
	// Via is the tag of another tunnel that carries this one's outer transport, which the
	// browser sends straight from the row's Dialer Proxy select: that one control is how
	// a chain is asked for on every outbound, tunnel or not. Blank is the ordinary case
	// and blank is also what an older panel posts, which is why it binds as a plain
	// string rather than through anything that would fail on absence.
	Via      string `form:"via"`
	Settings string `form:"settings"`
}

// vpnOutKindInfo is one entry of the outbound protocol picker.
type vpnOutKindInfo struct {
	Kind      string `json:"kind"`
	Available bool   `json:"available"`
	// Why is set only when Available is false, so the UI has a single thing to test.
	// One line for an operator, naming what is missing.
	Why string `json:"why"`
}

// vpnOutKindList builds the picker: every protocol whose driver compiled in, each
// marked with whether this HOST can actually run it.
//
// Availability travels WITH the kind rather than filtering it out. A protocol that
// is simply absent from the list looks like a panel that does not support it, and
// the operator has nothing to act on; a greyed-out entry carrying "the client binary
// was not included in this build" is a different message entirely. It also cannot be
// left to the save: the driver is asked the same question there and refuses, so
// without this the only way to discover a missing client is to fill the whole modal
// in and submit it.
func vpnOutKindList() []vpnOutKindInfo {
	// Order is VpnOutKinds's, which is sorted, so the picker does not reshuffle
	// between loads.
	kinds := service.VpnOutKinds()
	out := make([]vpnOutKindInfo, 0, len(kinds))
	for _, k := range kinds {
		// Asked through the service rather than by type-asserting the driver here:
		// Available is optional, and this is the one place that already answers for
		// the drivers that do not implement it.
		ok, why := service.VpnOutKindAvailable(k)
		if ok {
			why = ""
		}
		out = append(out, vpnOutKindInfo{Kind: k, Available: ok, Why: why})
	}
	return out
}

// vpnoutbound drives operator-configured VPN client tunnels used as egress
// (list/save/delete/status/kinds). Each tunnel is backed by a synthesized tagged
// `freedom` outbound pinned to the netdev the driver brought up, so it is
// reverse/routing-selectable purely by that tag - the same shape as the SSH tunnels
// above. Form-urlencoded, per the panel convention (no JSON binding).
func (a *XraySettingController) vpnoutbound(c *gin.Context) {
	switch c.Param("action") {
	case "list":
		jsonObj(c, a.VpnOutboundService.List(), nil)
	case "kinds":
		jsonObj(c, vpnOutKindList(), nil)
	case "save":
		var f vpnOutboundForm
		if err := c.ShouldBind(&f); err != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
			return
		}
		cfg := service.VpnOutboundConfig{
			Tag:    f.Tag,
			Kind:   f.Kind,
			Remark: f.Remark,
			Enable: f.Enable,
			Via:    f.Via,
		}
		// Rejected here rather than left to the driver, because a malformed blob does
		// not stop at the driver: it survives Validate if the driver only looks at the
		// fields it knows, then breaks the marshal of the WHOLE tunnel list in persist,
		// which reports itself as a failed save of an unrelated field.
		if raw := strings.TrimSpace(f.Settings); raw != "" {
			if !json.Valid([]byte(raw)) {
				jsonMsg(c, I18nWeb(c, "somethingWentWrong"), common.NewError("settings is not valid JSON"))
				return
			}
			cfg.Settings = json.RawMessage(raw)
		}
		// Settings go through as posted. Save restores the keys the panel could not
		// send (it is served a masked list) under the same lock it writes with.
		saved, err := a.VpnOutboundService.Save(cfg)
		if err != nil {
			jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
			return
		}
		// The interface goes back to the caller for the same reason the SSH tunnel's
		// socks port does: the driver picked it while bringing the tunnel up, it is what
		// the synthesized outbound binds to, and only the server knows it.
		jsonObj(c, gin.H{"iface": saved.Iface}, nil)
	case "delete":
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), a.VpnOutboundService.Delete(c.PostForm("tag")))
	case "status":
		up, detail := a.VpnOutboundService.Status(c.PostForm("tag"))
		jsonObj(c, gin.H{"running": up, "detail": detail}, nil)
	default:
		jsonObj(c, a.VpnOutboundService.List(), nil)
	}
}

// nord handles NordVPN-related operations based on the action parameter.
func (a *XraySettingController) nord(c *gin.Context) {
	action := c.Param("action")
	var resp string
	var err error
	switch action {
	case "countries":
		resp, err = a.NordService.GetCountries()
	case "servers":
		countryId := c.PostForm("countryId")
		resp, err = a.NordService.GetServers(countryId)
	case "reg":
		token := c.PostForm("token")
		resp, err = a.NordService.GetCredentials(token)
	case "setKey":
		key := c.PostForm("key")
		resp, err = a.NordService.SetKey(key)
	case "data":
		resp, err = a.NordService.GetNordData()
	case "del":
		err = a.NordService.DelNordData()
	}

	jsonObj(c, resp, err)
}

// getOutboundsTraffic retrieves the traffic statistics for outbounds.
func (a *XraySettingController) getOutboundsTraffic(c *gin.Context) {
	outboundsTraffic, err := a.OutboundService.GetOutboundsTraffic()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getOutboundTrafficError"), err)
		return
	}
	jsonObj(c, outboundsTraffic, nil)
}

// resetOutboundsTraffic resets the traffic statistics for the specified outbound tag.
func (a *XraySettingController) resetOutboundsTraffic(c *gin.Context) {
	tag := c.PostForm("tag")
	err := a.OutboundService.ResetOutboundTraffic(tag)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.resetOutboundTrafficError"), err)
		return
	}
	jsonObj(c, "", nil)
}

// testOutbound tests an outbound configuration and returns the delay/response time.
// Optional form "allOutbounds": JSON array of all outbounds; used to resolve sockopt.dialerProxy dependencies.
func (a *XraySettingController) testOutbound(c *gin.Context) {
	outboundJSON := c.PostForm("outbound")
	allOutboundsJSON := c.PostForm("allOutbounds")

	if outboundJSON == "" {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), common.NewError("outbound parameter is required"))
		return
	}

	// Load the test URL from server settings to prevent SSRF via user-controlled URLs
	testURL, _ := a.SettingService.GetXrayOutboundTestUrl()

	result, err := a.OutboundService.TestOutbound(outboundJSON, testURL, allOutboundsJSON)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	jsonObj(c, result, nil)
}
