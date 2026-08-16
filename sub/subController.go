package sub

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/web/service"
	"github.com/hasan1808/pro-ui/xray"

	"github.com/gin-gonic/gin"
)

// SUBController handles HTTP requests for subscription links and JSON configurations.
type SUBController struct {
	subTitle         string
	subSupportUrl    string
	subProfileUrl    string
	subAnnounce      string
	subEnableRouting bool
	subRoutingRules  string
	subPath          string
	subJsonPath      string
	subClashPath     string
	jsonEnabled      bool
	clashEnabled     bool
	subEncrypt       bool
	updateInterval   string

	subService      *SubService
	subJsonService  *SubJsonService
	subClashService *SubClashService
}

// NewSUBController creates a new subscription controller with the given configuration.
func NewSUBController(
	g *gin.RouterGroup,
	subPath string,
	jsonPath string,
	clashPath string,
	jsonEnabled bool,
	clashEnabled bool,
	encrypt bool,
	showInfo bool,
	rModel string,
	update string,
	jsonFragment string,
	jsonNoise string,
	jsonMux string,
	jsonRules string,
	subTitle string,
	subSupportUrl string,
	subProfileUrl string,
	subAnnounce string,
	subEnableRouting bool,
	subRoutingRules string,
) *SUBController {
	sub := NewSubService(showInfo, rModel)
	a := &SUBController{
		subTitle:         subTitle,
		subSupportUrl:    subSupportUrl,
		subProfileUrl:    subProfileUrl,
		subAnnounce:      subAnnounce,
		subEnableRouting: subEnableRouting,
		subRoutingRules:  subRoutingRules,
		subPath:          subPath,
		subJsonPath:      jsonPath,
		subClashPath:     clashPath,
		jsonEnabled:      jsonEnabled,
		clashEnabled:     clashEnabled,
		subEncrypt:       encrypt,
		updateInterval:   update,

		subService:      sub,
		subJsonService:  NewSubJsonService(jsonFragment, jsonNoise, jsonMux, jsonRules, sub),
		subClashService: NewSubClashService(sub),
	}
	a.initRouter(g)
	return a
}

// initRouter registers HTTP routes for subscription links and JSON endpoints
// on the provided router group.
func (a *SUBController) initRouter(g *gin.RouterGroup) {
	gLink := g.Group(a.subPath)
	gLink.GET(":subid", a.subs)
	// Client config downloads offered by the subscriber page (OpenVPN .ovpn, wg-c/awg
	// .conf). Under the raw sub path so it inherits the same host, port and base path,
	// and so the subId stays the only credential involved.
	gLink.GET(":subid/configs/:key", a.subConfig)
	if a.jsonEnabled {
		gJson := g.Group(a.subJsonPath)
		gJson.GET(":subid", a.subJsons)
	}
	if a.clashEnabled {
		gClash := g.Group(a.subClashPath)
		gClash.GET(":subid", a.subClashs)
	}
}

// subs handles HTTP requests for subscription links, returning either HTML page or
// the payload rendered by the operator-chosen template (base64/plain/clash/json/custom).
func (a *SUBController) subs(c *gin.Context) {
	subId := c.Param("subid")
	scheme, host, hostWithPort, hostHeader := a.subService.ResolveRequest(c)
	subs, lastOnline, traffic, err := a.subService.GetSubs(subId, host)
	// An empty link list is NOT an error: an account whose only inbounds are wg-c/awg
	// has real usage and a real expiry to report, but no single-line raw form (its
	// config comes from the Clash sub). Erroring here would hide the traffic/days page
	// from exactly those accounts. GetSubs already errors when the subId matches nothing.
	if err != nil {
		c.String(400, "Error!")
		return
	}

	// If the request expects HTML (e.g., browser) or explicitly asked (?html=1 or ?view=html), render the info page here
	accept := c.GetHeader("Accept")
	if strings.Contains(strings.ToLower(accept), "text/html") || c.Query("html") == "1" || strings.EqualFold(c.Query("view"), "html") {
		// Build page data in service
		subURL, subJsonURL, subClashURL := a.subService.BuildURLs(scheme, hostWithPort, a.subPath, a.subJsonPath, a.subClashPath, subId)
		if !a.jsonEnabled {
			subJsonURL = ""
		}
		if !a.clashEnabled {
			subClashURL = ""
		}
		// Get base_path from context (set by middleware)
		basePath, exists := c.Get("base_path")
		if !exists {
			basePath = "/"
		}
		// Add subId to base_path for asset URLs
		basePathStr := basePath.(string)
		if basePathStr == "/" {
			basePathStr = "/" + subId + "/"
		} else {
			// Remove trailing slash if exists, add subId, then add trailing slash
			basePathStr = strings.TrimRight(basePathStr, "/") + "/" + subId + "/"
		}
		page := a.subService.BuildPageData(subId, hostHeader, traffic, lastOnline, subs, subURL, subJsonURL, subClashURL, basePathStr)
		// OpenVPN and WireGuard cannot be set up from a link: the page offers their
		// config files as downloads. Rendered only for the browser view, since a
		// subscription client has no use for them.
		page.Configs = a.subService.ConfigLinks(subId, host, scheme, hostWithPort, a.subPath)
		c.HTML(200, "subpage.html", gin.H{
			"title":        "subscription.title",
			"cur_ver":      config.GetVersion(),
			"host":         page.Host,
			"base_path":    page.BasePath,
			"sId":          page.SId,
			"download":     page.Download,
			"upload":       page.Upload,
			"total":        page.Total,
			"used":         page.Used,
			"remained":     page.Remained,
			"expire":       page.Expire,
			"lastOnline":   page.LastOnline,
			"datepicker":   page.Datepicker,
			"downloadByte": page.DownloadByte,
			"uploadByte":   page.UploadByte,
			"totalByte":    page.TotalByte,
			"subUrl":       page.SubUrl,
			"subJsonUrl":   page.SubJsonUrl,
			"subClashUrl":  page.SubClashUrl,
			"result":       page.Result,
			"configs":      page.Configs,
			"email":        page.Email,
			"password":     page.Password,
		})
		return
	}

	profileUrl := a.subProfileUrl
	if profileUrl == "" {
		profileUrl = fmt.Sprintf("%s://%s%s", scheme, hostWithPort, c.Request.RequestURI)
	}

	// The operator-chosen template is read from the settings table PER REQUEST (a
	// zero-value SettingService reads live), so saving a new template in the panel
	// applies to the running sub server immediately — no restart, unlike the other
	// sub options which are snapshotted at Start(). Unknown values fall back to the
	// legacy base64 behaviour (the switch's default) so a config written by a future
	// version never breaks the raw link outright.
	var ss service.SettingService
	template, _ := ss.GetSubTemplate()

	switch template {
	case "plain":
		header := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules)
		c.String(200, strings.Join(subs, "\n"))
	case "json":
		jsonSub, header, err := a.subJsonService.GetJson(subId, host)
		if err != nil || len(jsonSub) == 0 {
			// No JSON form for this account's protocols (e.g. openvpn/l2tp);
			// serve the raw links instead so a template choice never breaks the link.
			a.serveRawLinks(c, subs, traffic, profileUrl)
			return
		}
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules)
		c.String(200, jsonSub)
	case "clash":
		clashSub, header, err := a.subClashService.GetClash(subId, host)
		if err != nil || len(clashSub) == 0 {
			// Same fallback as json: protocols with no Clash proxy (naive, mtproto,
			// ssh, gre) still get the raw links instead of "Error!".
			a.serveRawLinks(c, subs, traffic, profileUrl)
			return
		}
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules)
		c.Data(200, "application/yaml; charset=utf-8", []byte(clashSub))
	case "custom":
		custom, _ := ss.GetSubCustomTemplate()
		email, _ := a.subService.accountCredential(subId)
		content := renderSubTemplate(custom, subTemplateVars{
			Links:    strings.Join(subs, "\n"),
			Email:    email,
			SubTitle: a.subTitle,
			Up:       traffic.Up,
			Down:     traffic.Down,
			Total:    traffic.Total,
			Expire:   traffic.ExpiryTime / 1000,
		})
		header := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules)
		c.String(200, content)
	default: // "base64"
		result := strings.Join(subs, "\n")
		header := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules)
		if a.subEncrypt {
			c.String(200, base64.StdEncoding.EncodeToString([]byte(result)))
		} else {
			c.String(200, result)
		}
	}
}

// serveRawLinks serves the account's raw links (base64-encoded when subEncrypt is
// set) with the standard headers. It is the fallback for templates that have no
// representation of the account's protocols, so a template choice never turns a
// working link into "Error!".
func (a *SUBController) serveRawLinks(c *gin.Context, subs []string, traffic xray.ClientTraffic, profileUrl string) {
	result := strings.Join(subs, "\n")
	header := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
	a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules)
	if a.subEncrypt {
		c.String(200, base64.StdEncoding.EncodeToString([]byte(result)))
	} else {
		c.String(200, result)
	}
}

// subConfig serves one client config file (an OpenVPN .ovpn or a WireGuard/AmneziaWG
// .conf) for the account behind the subId. The key names an inbound and variant; anything
// that does not resolve to a config this subscription owns is a flat 404, so the route
// says nothing about inbounds the caller has no subId for.
func (a *SUBController) subConfig(c *gin.Context) {
	subId := c.Param("subid")
	_, host, _, _ := a.subService.ResolveRequest(c)
	cfg, ok := a.subService.ConfigFile(subId, host, c.Param("key"))
	if !ok {
		c.String(404, "Not found")
		return
	}
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", cfg.Filename))
	c.Data(200, cfg.ContentType+"; charset=utf-8", []byte(cfg.Content))
}

// subJsons handles HTTP requests for JSON subscription configurations.
func (a *SUBController) subJsons(c *gin.Context) {
	subId := c.Param("subid")
	scheme, host, hostWithPort, _ := a.subService.ResolveRequest(c)
	jsonSub, header, err := a.subJsonService.GetJson(subId, host)
	if err != nil || len(jsonSub) == 0 {
		c.String(400, "Error!")
	} else {
		profileUrl := a.subProfileUrl
		if profileUrl == "" {
			profileUrl = fmt.Sprintf("%s://%s%s", scheme, hostWithPort, c.Request.RequestURI)
		}
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules)

		c.String(200, jsonSub)
	}
}

func (a *SUBController) subClashs(c *gin.Context) {
	subId := c.Param("subid")
	scheme, host, hostWithPort, _ := a.subService.ResolveRequest(c)
	clashSub, header, err := a.subClashService.GetClash(subId, host)
	if err != nil || len(clashSub) == 0 {
		c.String(400, "Error!")
	} else {
		profileUrl := a.subProfileUrl
		if profileUrl == "" {
			profileUrl = fmt.Sprintf("%s://%s%s", scheme, hostWithPort, c.Request.RequestURI)
		}
		a.ApplyCommonHeaders(c, header, a.updateInterval, a.subTitle, a.subSupportUrl, profileUrl, a.subAnnounce, a.subEnableRouting, a.subRoutingRules)
		c.Data(200, "application/yaml; charset=utf-8", []byte(clashSub))
	}
}

// ApplyCommonHeaders sets common HTTP headers for subscription responses including user info, update interval, and profile title.
func (a *SUBController) ApplyCommonHeaders(
	c *gin.Context,
	header,
	updateInterval,
	profileTitle string,
	profileSupportUrl string,
	profileUrl string,
	profileAnnounce string,
	profileEnableRouting bool,
	profileRoutingRules string,
) {
	c.Writer.Header().Set("Subscription-Userinfo", header)
	c.Writer.Header().Set("Profile-Update-Interval", updateInterval)

	//Basics
	if profileTitle != "" {
		c.Writer.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(profileTitle)))
	}
	if profileSupportUrl != "" {
		c.Writer.Header().Set("Support-Url", profileSupportUrl)
	}
	if profileUrl != "" {
		c.Writer.Header().Set("Profile-Web-Page-Url", profileUrl)
	}
	if profileAnnounce != "" {
		c.Writer.Header().Set("Announce", "base64:"+base64.StdEncoding.EncodeToString([]byte(profileAnnounce)))
	}

	//Advanced (Happ)
	c.Writer.Header().Set("Routing-Enable", strconv.FormatBool(profileEnableRouting))
	if profileRoutingRules != "" {
		c.Writer.Header().Set("Routing", profileRoutingRules)
	}
}
