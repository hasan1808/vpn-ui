package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/service"

	"github.com/gin-gonic/gin"
	"github.com/op/go-logging"
)

// probeVpnOutDriver stands in for a real protocol driver. It records the config it
// was handed, which is what these assert against: Save folds the stored settings in
// BEFORE it validates, so whatever reaches Validate is the merged result the driver
// would really have to work with.
type probeVpnOutDriver struct{ kind string }

func (d probeVpnOutDriver) Up(cfg service.VpnOutboundConfig) (string, error) {
	return "probe0", nil
}
func (d probeVpnOutDriver) Down(cfg service.VpnOutboundConfig) error { return nil }
func (d probeVpnOutDriver) Status(cfg service.VpnOutboundConfig) (bool, string) {
	return false, ""
}
func (d probeVpnOutDriver) Validate(cfg service.VpnOutboundConfig) error {
	probeSeen = cfg
	return probeValidateErr
}

// probeSecretDriver declares a secret key so List has something to mask. It is a
// separate kind rather than a flag on the plain probe because masking changes what
// every other test would see coming back out of a list.
type probeSecretDriver struct{ probeVpnOutDriver }

func (probeSecretDriver) SecretKeys() []string { return []string{"privateKey"} }

// probeUnavailableDriver stands for a protocol whose client is missing from this
// build, which is a RUNTIME fact: the bundle is embedded with `all:bin`, so an
// absent binary compiles fine and only fails when the tunnel is raised.
type probeUnavailableDriver struct{ probeVpnOutDriver }

func (probeUnavailableDriver) Available() (bool, string) {
	return false, "the probe client was not included in this build"
}

const (
	probeKind = "controllerprobe"
	// A second kind, to prove settings are NOT carried across a protocol change.
	probeKindAlt = "controllerprobealt"
	// A third, whose driver declares a secret.
	probeKindSecret = "controllerprobesecret"
	// A fourth, whose driver reports itself unusable on this host.
	probeKindGone = "controllerprobegone"
)

var (
	probeSeen        service.VpnOutboundConfig
	probeValidateErr error
)

func init() {
	service.RegisterVpnOutDriver(probeKind, probeVpnOutDriver{kind: probeKind})
	service.RegisterVpnOutDriver(probeKindAlt, probeVpnOutDriver{kind: probeKindAlt})
	service.RegisterVpnOutDriver(probeKindSecret,
		probeSecretDriver{probeVpnOutDriver{kind: probeKindSecret}})
	service.RegisterVpnOutDriver(probeKindGone,
		probeUnavailableDriver{probeVpnOutDriver{kind: probeKindGone}})
}

func newVpnOutTestDB(t *testing.T) {
	t.Helper()
	// jsonMsg logs every failure it reports, and the package logger is a nil pointer
	// until something initialises it (main does, a test binary does not), which turns
	// an error response into a segfault rather than a test failure.
	logger.InitLogger(logging.CRITICAL)
	if err := database.InitDB(filepath.Join(t.TempDir(), "vpnout.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	probeSeen = service.VpnOutboundConfig{}
	probeValidateErr = nil
}

// postVpnOutbound drives the real handler over a real Gin stack with a
// form-urlencoded body, which is the only shape the panel ever sends.
func postVpnOutbound(t *testing.T, action, body string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	a := &XraySettingController{}
	r := gin.New()
	r.POST("/xray/vpnoutbound/:action", withUser(nil), a.vpnoutbound)

	req := httptest.NewRequest(http.MethodPost, "/xray/vpnoutbound/"+action, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: HTTP %d, want 200 (the panel reads failures out of the body)", action, w.Code)
	}
	return w.Body.String()
}

// saveTunnel posts a save and fails the test if the panel would have seen an error.
//
// Saved DISABLED on purpose. Enabling one makes the framework raise the tunnel for
// real, which means netlink: a route table and an ip rule for the device the driver
// named. That needs CAP_NET_ADMIN and would edit the routing of whatever machine ran
// the tests. Nothing here depends on it, because the settings merge happens before
// the tunnel is touched.
func saveTunnel(t *testing.T, tag, kind, settings string) {
	t.Helper()
	body := "tag=" + tag + "&kind=" + kind + "&enable=false&settings=" + urlEncode(settings)
	if got := postVpnOutbound(t, "save", body); strings.Contains(got, `"success":false`) {
		t.Fatalf("save %s: %s", tag, got)
	}
}

// seenSetting reads one key out of the settings the driver was handed.
func seenSetting(t *testing.T, key string) (any, bool) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(probeSeen.Settings, &m); err != nil {
		t.Fatalf("driver got un-parseable settings %q: %v", string(probeSeen.Settings), err)
	}
	v, ok := m[key]
	return v, ok
}

// The nested settings blob is the whole reason this handler does not bind straight
// into VpnOutboundConfig: that struct's Settings is a json.RawMessage, i.e. a byte
// slice, and Gin's form binder maps a slice element by element through ParseUint. A
// JSON object there fails the entire bind, and an EMPTY field binds to a one-byte
// \x00 that is not valid JSON and would poison the stored tunnel list. Both are
// silent at compile time, so they are pinned here.
//
// Asserts on what reached the DRIVER rather than on the response: enable=true is
// kept because binding a bool off a form is part of what is under test, and the
// save behind it then stops in netlink for want of a real netdev. Validate runs
// first, so the config is already captured by then.
func TestVpnOutboundSaveCarriesNestedSettings(t *testing.T) {
	newVpnOutTestDB(t)
	settings := `{"privateKey":"abc","peers":[{"endpoint":"1.2.3.4:51820"}]}`
	body := "tag=probe1&kind=" + probeKind + "&remark=my+tunnel&enable=true" +
		"&settings=" + urlEncode(settings)

	postVpnOutbound(t, "save", body)

	if probeSeen.Tag != "probe1" || probeSeen.Kind != probeKind {
		t.Fatalf("scalar fields lost: %+v", probeSeen)
	}
	if probeSeen.Remark != "my tunnel" || !probeSeen.Enable {
		t.Fatalf("remark/enable lost: %+v", probeSeen)
	}
	if got := string(probeSeen.Settings); got != settings {
		t.Fatalf("settings blob = %q, want %q", got, settings)
	}
}

// An absent or empty settings field must leave Settings nil rather than the \x00
// blob a direct bind produces, because that byte reaches the driver as its config
// and, if the driver tolerates it, gets marshalled into the stored list.
func TestVpnOutboundSaveEmptySettingsStaysNil(t *testing.T) {
	for _, body := range []string{
		"tag=probe2&kind=" + probeKind + "&enable=false",
		"tag=probe2&kind=" + probeKind + "&enable=false&settings=",
		"tag=probe2&kind=" + probeKind + "&enable=false&settings=%20",
	} {
		newVpnOutTestDB(t)
		postVpnOutbound(t, "save", body)
		if len(probeSeen.Settings) != 0 {
			t.Fatalf("body %q left settings = %q, want empty", body, string(probeSeen.Settings))
		}
	}
}

// A malformed blob is rejected at the edge. Left to the framework it would survive
// as far as persist(), where marshalling the whole list fails on it and the operator
// is told the save broke rather than which field did.
func TestVpnOutboundSaveRejectsInvalidJson(t *testing.T) {
	newVpnOutTestDB(t)
	body := "tag=probe3&kind=" + probeKind + "&enable=true&settings=" + urlEncode("{nope")

	got := postVpnOutbound(t, "save", body)

	if !strings.Contains(got, "not valid JSON") {
		t.Fatalf("response = %s, want a settings-JSON complaint", got)
	}
	if probeSeen.Kind != "" {
		t.Fatalf("a malformed blob reached the driver: %+v", probeSeen)
	}
}

// Editing a saved tunnel without re-sending its secrets. The modal never renders a
// stored private key, so it omits the key entirely; the stored value has to survive.
// Without this, changing an MTU means re-pasting every credential.
func TestVpnOutboundSaveKeepsUnsentSettings(t *testing.T) {
	newVpnOutTestDB(t)
	saveTunnel(t, "keep", probeKind, `{"privateKey":"s3cret","mtu":1400,"remote":"vpn.example"}`)

	// The edit the panel actually sends: one changed field, secrets omitted.
	saveTunnel(t, "keep", probeKind, `{"mtu":1500}`)

	if v, ok := seenSetting(t, "privateKey"); !ok || v != "s3cret" {
		t.Fatalf("privateKey = %v (present=%v), want it kept", v, ok)
	}
	if v, _ := seenSetting(t, "remote"); v != "vpn.example" {
		t.Fatalf("remote = %v, want it kept", v)
	}
	if v, _ := seenSetting(t, "mtu"); v != float64(1500) {
		t.Fatalf("mtu = %v, want the posted 1500", v)
	}
}

// Keeping an unsent key must not make a field unclearable: a key that IS sent wins,
// including when its value is empty.
func TestVpnOutboundSaveClearsExplicitlyEmptied(t *testing.T) {
	newVpnOutTestDB(t)
	saveTunnel(t, "clear", probeKind, `{"privateKey":"s3cret","mtu":1400}`)

	saveTunnel(t, "clear", probeKind, `{"privateKey":""}`)

	if v, ok := seenSetting(t, "privateKey"); !ok || v != "" {
		t.Fatalf("privateKey = %v (present=%v), want it cleared", v, ok)
	}
	if v, _ := seenSetting(t, "mtu"); v != float64(1400) {
		t.Fatalf("mtu = %v, want the untouched 1400", v)
	}
}

// Switching a tag to another protocol is a different settings shape, so nothing is
// carried over. Merging there would hand the new driver keys it never defined.
func TestVpnOutboundSaveDoesNotMergeAcrossKinds(t *testing.T) {
	newVpnOutTestDB(t)
	saveTunnel(t, "switch", probeKind, `{"privateKey":"s3cret","mtu":1400}`)

	saveTunnel(t, "switch", probeKindAlt, `{"profile":"other"}`)

	if v, ok := seenSetting(t, "privateKey"); ok {
		t.Fatalf("privateKey = %v leaked into the new protocol's settings", v)
	}
	if v, _ := seenSetting(t, "profile"); v != "other" {
		t.Fatalf("profile = %v, want the posted value", v)
	}
}

// A kept value is round-tripped through a decode and a re-encode, so it must come
// back byte for byte. The obvious way to write that merge, decoding into
// map[string]any, turns every number into a float64: an integer past 2^53 is then
// silently mangled and can be re-emitted in exponent notation, corrupting a stored
// value nobody edited.
func TestVpnOutboundSaveKeepsLargeNumbersExact(t *testing.T) {
	newVpnOutTestDB(t)
	saveTunnel(t, "bignum", probeKind, `{"id":9007199254740993,"mtu":1400}`)

	saveTunnel(t, "bignum", probeKind, `{"mtu":1500}`)

	if !strings.Contains(string(probeSeen.Settings), `"id":9007199254740993`) {
		t.Fatalf("settings = %s, want the id literal preserved", string(probeSeen.Settings))
	}
}

// A save the driver refuses must not reach the store, so the next read still sees
// the previous tunnel.
func TestVpnOutboundSaveReportsDriverRejection(t *testing.T) {
	newVpnOutTestDB(t)
	probeValidateErr = errors.New("a private key is required")

	got := postVpnOutbound(t, "save",
		"tag=bad&kind="+probeKind+"&enable=true&settings="+urlEncode(`{"mtu":1400}`))

	if !strings.Contains(got, "a private key is required") {
		t.Fatalf("response = %s, want the driver's own complaint", got)
	}
	probeValidateErr = nil
	if list := postVpnOutbound(t, "list", ""); strings.Contains(list, `"tag":"bad"`) {
		t.Fatalf("a rejected tunnel was stored: %s", list)
	}
}

// The two halves of the secret contract, over the wire, in the order the panel hits
// them. Masking on its own would make a tunnel uneditable and keep-on-blank on its
// own leaves credentials in the response body; only together do they work, so they
// are asserted together.
func TestVpnOutboundSecretsAreMaskedAndSurviveAnEdit(t *testing.T) {
	newVpnOutTestDB(t)
	saveTunnel(t, "masked", probeKindSecret, `{"privateKey":"s3cret","mtu":1400}`)

	list := postVpnOutbound(t, "list", "")
	if strings.Contains(list, "s3cret") {
		t.Fatalf("list handed a declared secret to the browser: %s", list)
	}
	if !strings.Contains(list, `"mtu":1400`) {
		t.Fatalf("list dropped a field that is not a secret: %s", list)
	}

	// The panel cannot send back what it was never given, so an edit that omits the
	// masked key has to keep it rather than clear it.
	saveTunnel(t, "masked", probeKindSecret, `{"mtu":1500}`)

	if v, ok := seenSetting(t, "privateKey"); !ok || v != "s3cret" {
		t.Fatalf("privateKey = %v (present=%v), want the stored secret restored", v, ok)
	}
	if v, _ := seenSetting(t, "mtu"); v != float64(1500) {
		t.Fatalf("mtu = %v, want the posted 1500", v)
	}
}

// The picker is server-driven so a protocol whose driver is not compiled in cannot
// be offered, and each entry says whether this host can actually run it. A protocol
// that is merely unusable is listed and disabled rather than hidden, so the operator
// is told what is missing instead of concluding the panel does not support it.
func TestVpnOutboundKindsReportsAvailability(t *testing.T) {
	newVpnOutTestDB(t)

	var got struct {
		Obj []struct {
			Kind      string `json:"kind"`
			Available bool   `json:"available"`
			Why       string `json:"why"`
		} `json:"obj"`
	}
	if err := json.Unmarshal([]byte(postVpnOutbound(t, "kinds", "")), &got); err != nil {
		t.Fatalf("kinds response: %v", err)
	}

	seen := map[string]struct {
		available bool
		why       string
	}{}
	order := make([]string, 0, len(got.Obj))
	for _, k := range got.Obj {
		seen[k.Kind] = struct {
			available bool
			why       string
		}{k.Available, k.Why}
		order = append(order, k.Kind)
	}

	// A driver with no Available method is usable, and carries no reason to show.
	plain, ok := seen[probeKind]
	if !ok {
		t.Fatalf("kinds omitted the plain probe driver: %v", order)
	}
	if !plain.available || plain.why != "" {
		t.Fatalf("plain driver = %+v, want available with no reason", plain)
	}

	// One that reports itself unusable is still listed, with the reason to display.
	gone, ok := seen[probeKindGone]
	if !ok {
		t.Fatalf("kinds dropped the unavailable driver instead of disabling it: %v", order)
	}
	if gone.available {
		t.Fatalf("unavailable driver = %+v, want available:false", gone)
	}
	if !strings.Contains(gone.why, "not included in this build") {
		t.Fatalf("why = %q, want the driver's own explanation", gone.why)
	}

	if !sort.StringsAreSorted(order) {
		t.Fatalf("kinds order = %v, want it stable and sorted", order)
	}
}

func urlEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}
