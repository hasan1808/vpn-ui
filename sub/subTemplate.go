package sub

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/web/service"
)

// subTemplateVars are the values a custom subscription template can interpolate.
type subTemplateVars struct {
	Links    string // every subscription link, one per line
	SubTitle string // the configured subscription title
	Email    string // the account's username / email
	Up       int64  // used traffic (bytes)
	Down     int64  // downloaded traffic (bytes)
	Total    int64  // total quota (bytes)
	Expire   int64  // expiry as Unix seconds (0 = none)
	Date     string // today's date (YYYY-MM-DD)
}

// subTemplateVarRe matches the $variables a custom template can reference. The
// leading "$" makes the first character special, so a bare literal "$" is never a
// valid name on its own; an unknown name is left in place so the operator sees the
// typo in the output instead of a silently empty line.
var subTemplateVarRe = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*`)

// renderSubTemplate substitutes the known placeholders in a custom template body.
// Unknown $vars survive untouched.
func renderSubTemplate(tpl string, v subTemplateVars) string {
	if v.Date == "" {
		v.Date = time.Now().Format("2006-01-02")
	}
	values := map[string]string{
		"$links":    v.Links,
		"$subtitle": v.SubTitle,
		"$email":    v.Email,
		"$up":       strconv.FormatInt(v.Up, 10),
		"$down":     strconv.FormatInt(v.Down, 10),
		"$total":    strconv.FormatInt(v.Total, 10),
		"$expire":   strconv.FormatInt(v.Expire, 10),
		"$date":     v.Date,
	}
	return subTemplateVarRe.ReplaceAllStringFunc(tpl, func(m string) string {
		if val, ok := values[m]; ok {
			return val
		}
		return m
	})
}

// previewSubService builds the raw-link SubService from the operator's CURRENTLY
// SAVED display settings, so the preview matches what a subscriber gets. The
// template choice itself comes from the preview request (it may be unsaved).
func previewSubService(ss service.SettingService) *SubService {
	showInfo, _ := ss.GetSubShowInfo()
	remark, _ := ss.GetRemarkModel()
	if remark == "" {
		remark = "-ieo"
	}
	return NewSubService(showInfo, remark)
}

// RenderTemplate renders the subscription payload for the given template and custom
// body against a real subId, exactly as the /sub/:subid endpoint would serve it.
// Used by the panel's settings preview so the operator can inspect a format before
// saving it. The operator's currently-saved settings drive the JSON/Clash services
// (fragment, noises, mux, rules) and the display options (show info, remark model).
func RenderTemplate(subId, host, template, custom string) (string, error) {
	var ss service.SettingService

	switch template {
	case "plain", "base64":
		sub := previewSubService(ss)
		subs, _, _, err := sub.GetSubs(subId, host)
		if err != nil {
			return "", err
		}
		content := strings.Join(subs, "\n")
		if template == "base64" {
			content = base64.StdEncoding.EncodeToString([]byte(content))
		}
		return content, nil
	case "json":
		fragment, _ := ss.GetSubJsonFragment()
		noises, _ := ss.GetSubJsonNoises()
		mux, _ := ss.GetSubJsonMux()
		rules, _ := ss.GetSubJsonRules()
		content, _, err := NewSubJsonService(fragment, noises, mux, rules, previewSubService(ss)).GetJson(subId, host)
		return content, err
	case "clash":
		content, _, err := NewSubClashService(previewSubService(ss)).GetClash(subId, host)
		return content, err
	case "custom":
		sub := previewSubService(ss)
		subs, _, traffic, err := sub.GetSubs(subId, host)
		if err != nil {
			return "", err
		}
		email, _ := sub.accountCredential(subId)
		title, _ := ss.GetSubTitle()
		return renderSubTemplate(custom, subTemplateVars{
			Links:    strings.Join(subs, "\n"),
			Email:    email,
			SubTitle: title,
			Up:       traffic.Up,
			Down:     traffic.Down,
			Total:    traffic.Total,
			Expire:   traffic.ExpiryTime / 1000,
		}), nil
	}
	// Unknown template: fall back to the legacy base64 payload.
	sub := previewSubService(ss)
	subs, _, _, err := sub.GetSubs(subId, host)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(subs, "\n"))), nil
}

// FirstSubId returns the subId of the first enabled client found on any inbound,
// and whether one exists. The settings preview uses it so the operator does not
// have to type an account id to see what a subscriber gets.
func FirstSubId() (string, bool) {
	var sub SubService
	db := database.GetDB()
	var inbounds []*model.Inbound
	if err := db.Model(model.Inbound{}).Where("enable = ?", true).Order("id ASC").Find(&inbounds).Error; err != nil {
		return "", false
	}
	for _, inbound := range inbounds {
		clients, err := sub.inboundService.GetClients(inbound)
		if err != nil {
			continue
		}
		for _, client := range clients {
			if client.Enable && client.SubID != "" {
				return client.SubID, true
			}
		}
	}
	return "", false
}
