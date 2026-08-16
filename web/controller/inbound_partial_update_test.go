package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"

	"github.com/gin-gonic/gin"
)

// UpdateInbound copies about twenty editable columns from the bound struct onto
// the stored row, and Gin leaves a field the request did not mention at its ZERO
// value. Binding onto an empty struct therefore turned every omitted field into a
// silent destructive write: renaming an inbound over the API also wiped its
// traffic multiplier, speed limits, IP limit and its own quota, with nothing
// reported because those were simply the values the server was sent.
func TestPartialInboundUpdatePreservesOmittedFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newIdorFixture(t)

	// Give Ali's inbound a full set of operator policy to lose.
	err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", f.aliInbound.Id).
		Updates(map[string]any{
			"traffic_multiplier_enable": true,
			"traffic_multiplier":        3.0,
			"traffic_multiplier_after":  int64(1024),
			"speed_limit_enable":        true,
			"speed_limit_down":          5000,
			"speed_limit_up":            2500,
			"speed_limit_after":         int64(2048),
			"ip_limit":                  7,
			"ip_limit_strategy":         "accept",
			"total":                     int64(999),
			"expiry_time":               int64(123456),
			"traffic_reset":             "monthly",
		}).Error
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	// The obvious way to rename an inbound over the API: send only what changed.
	body := url.Values{
		"remark":   {"renamed"},
		"port":     {fmt.Sprint(f.aliInbound.Port)},
		"protocol": {string(f.aliInbound.Protocol)},
		"enable":   {"true"},
		"settings": {f.aliInbound.Settings},
	}.Encode()
	w := f.as(t, f.ali, http.MethodPost,
		fmt.Sprintf("/panel/api/inbounds/update/%d", f.aliInbound.Id), body)
	if w.Code != http.StatusOK {
		t.Fatalf("update returned %d: %s", w.Code, w.Body.String())
	}

	var got model.Inbound
	if err := database.GetDB().Where("id = ?", f.aliInbound.Id).First(&got).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Remark != "renamed" {
		t.Fatalf("the edit did not apply at all (remark=%q); the rest of this test would be meaningless", got.Remark)
	}
	check := func(name string, got, want any) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v: a partial update silently destroyed it", name, got, want)
		}
	}
	check("TrafficMultiplierEnable", got.TrafficMultiplierEnable, true)
	check("TrafficMultiplier", got.TrafficMultiplier, 3.0)
	check("TrafficMultiplierAfter", got.TrafficMultiplierAfter, int64(1024))
	check("SpeedLimitEnable", got.SpeedLimitEnable, true)
	check("SpeedLimitDown", got.SpeedLimitDown, 5000)
	check("SpeedLimitUp", got.SpeedLimitUp, 2500)
	check("SpeedLimitAfter", got.SpeedLimitAfter, int64(2048))
	check("IPLimit", got.IPLimit, 7)
	check("IPLimitStrategy", got.IPLimitStrategy, "accept")
	check("Total", got.Total, int64(999))
	check("ExpiryTime", got.ExpiryTime, int64(123456))
	check("TrafficReset", got.TrafficReset, "monthly")
}

// The other direction, so the fix cannot become "omitted fields are ignored AND
// present ones are too". The panel posts the whole inbound object, so a value it
// sends must still overwrite the stored one, including turning a flag OFF.
func TestFullInboundUpdateStillOverwrites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := newIdorFixture(t)

	if err := database.GetDB().Model(&model.Inbound{}).Where("id = ?", f.aliInbound.Id).
		Updates(map[string]any{
			"speed_limit_enable": true,
			"speed_limit_down":   5000,
			"ip_limit":           7,
		}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := url.Values{
		"remark":           {"explicit"},
		"port":             {fmt.Sprint(f.aliInbound.Port)},
		"protocol":         {string(f.aliInbound.Protocol)},
		"enable":           {"true"},
		"settings":         {f.aliInbound.Settings},
		"speedLimitEnable": {"false"},
		"speedLimitDown":   {"0"},
		"ipLimit":          {"0"},
	}.Encode()
	w := f.as(t, f.ali, http.MethodPost,
		fmt.Sprintf("/panel/api/inbounds/update/%d", f.aliInbound.Id), body)
	if w.Code != http.StatusOK {
		t.Fatalf("update returned %d: %s", w.Code, w.Body.String())
	}

	var got model.Inbound
	if err := database.GetDB().Where("id = ?", f.aliInbound.Id).First(&got).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.SpeedLimitEnable {
		t.Error("SpeedLimitEnable stayed on: an explicitly sent false must turn it off")
	}
	if got.SpeedLimitDown != 0 {
		t.Errorf("SpeedLimitDown = %d, want 0", got.SpeedLimitDown)
	}
	if got.IPLimit != 0 {
		t.Errorf("IPLimit = %d, want 0", got.IPLimit)
	}
}
