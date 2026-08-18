package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// The connection modes, the FakeTLS domain and the device cap belong to the INBOUND.
// telemt applies each of them process-wide however they are stored, so these tests pin
// that the rendered config says so, and that an inbound written before the move is
// lifted onto the new shape at startup rather than left with no modes at all (which its
// patched reader would take for "unrestricted").
//
// The ad tag is NOT one of them and never moved: telemt keys tags per user, so it stays
// a per-client field. See TestMtprotoAdtagIsPerClient in mtproto_routing_test.go.

func mtprotoInboundWithSettings(t *testing.T, settings *mtprotoSettings) *model.Inbound {
	t.Helper()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return &model.Inbound{Id: 3, Port: 9443, Tag: "inbound-9443", Protocol: model.MTPROTO, Settings: string(raw)}
}

// tomlSection returns the lines of one [section] of a rendered config.
func tomlSection(cfg, header string) []string {
	start := strings.Index(cfg, header+"\n")
	if start < 0 {
		return nil
	}
	rest := cfg[start+len(header)+1:]
	if end := strings.Index(rest, "\n["); end >= 0 {
		rest = rest[:end]
	}
	var out []string
	for _, line := range strings.Split(rest, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// Every account gets the inbound's modes and its device cap. telemt reads both as
// per-USER maps and treats a MISSING entry as "no restriction", so the inbound-wide
// value has to be spelled out for each account rather than written once.
func TestMtprotoInboundSettingsApplyToEveryAccount(t *testing.T) {
	cap4 := 4
	inbound := mtprotoInboundWithSettings(t, &mtprotoSettings{
		ModeClassic: true,
		ModeTls:     true,
		TlsDomain:   "www.cloudflare.com",
		UserLimit:   &cap4,
		Clients: []mtprotoClient{
			{Email: "alice@t", Secret: "00112233445566778899aabbccddeeff", Enable: true},
			{Email: "bob@t", Secret: "ffeeddccbbaa99887766554433221100", Enable: true},
		},
	})
	s := &MtprotoService{}
	settings, err := s.parseSettings(inbound)
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.buildServerConfig(inbound, settings)

	for _, want := range []string{"classic = true", "secure = false", "tls = true"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("[general.modes] is missing %q; the listener would refuse a mode the inbound accepts", want)
		}
	}
	if !strings.Contains(cfg, `tls_domain = "www.cloudflare.com"`) {
		t.Error("the inbound's FakeTLS domain did not reach [censorship]")
	}

	for _, tc := range []struct{ section, want string }{
		{"[access.user_modes]", `= "classic,tls"`},
		{"[access.user_max_unique_ips]", "= 4"},
	} {
		lines := tomlSection(cfg, tc.section)
		if len(lines) != 2 {
			t.Errorf("%s has %d entries, want one per account (2): %v", tc.section, len(lines), lines)
			continue
		}
		for _, line := range lines {
			if !strings.HasSuffix(line, tc.want) {
				t.Errorf("%s entry %q does not carry the inbound value %q", tc.section, line, tc.want)
			}
		}
	}
}

// An inbound with every mode off must not be started. Its per-account mode entries
// would be EMPTY, which the telemt patch reads as "no restriction": the proxy would
// grant every account every mode, the exact opposite of what was configured.
func TestMtprotoInboundWithNoModeIsNotStartable(t *testing.T) {
	s := &MtprotoService{}
	settings := &mtprotoSettings{Clients: []mtprotoClient{
		{Email: "alice@t", Secret: "00112233445566778899aabbccddeeff", Enable: true},
	}}
	if s.startable(settings) {
		t.Error("an inbound with no connection mode reported startable")
	}
	settings.ModeSecure = true
	if !s.startable(settings) {
		t.Error("an inbound with one mode and one account should be startable")
	}
	settings.Clients = nil
	if s.startable(settings) {
		t.Error("an inbound with no usable account reported startable")
	}
}

// The one-shot upgrade of an inbound stored before these settings moved. It runs on
// the ORDINARY startup path (GenerateAllConfigs), not from MigrateDB, which never runs
// on a plain binary upgrade.
func TestMtprotoLiftClientSettingsToInbound(t *testing.T) {
	newInboundDB(t) // InitDB into a temp file
	db := database.GetDB()
	s := &MtprotoService{}

	// The legacy shape: the lifted settings on the clients, nothing on the inbound.
	// Modes differ per account, only one holds a FakeTLS domain, and the two device
	// caps disagree. bob also carries an ad tag, which must be left exactly where it
	// is: that field did not move.
	legacy := `{"clients":[
		{"id":"alice","email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true,
		 "modeClassic":true,"tlsDomain":"ignored.example","userLimit":2,"comment":"keep me"},
		{"id":"bob","email":"bob","secret":"ffeeddccbbaa99887766554433221100","enable":true,
		 "modeTls":true,"tlsDomain":"www.cloudflare.com","adtagEnable":true,
		 "adtag":"0123456789abcdef0123456789abcdef","userLimit":7}
	]}`
	inbound := &model.Inbound{UserId: 1, Tag: "inbound-9443", Port: 9443, Protocol: model.MTPROTO,
		Enable: true, Settings: legacy}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}

	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatalf("LiftClientSettingsToInbound: %v", err)
	}

	read := func() *mtprotoSettings {
		t.Helper()
		var stored model.Inbound
		if err := db.Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
			t.Fatalf("re-read inbound: %v", err)
		}
		out := &mtprotoSettings{}
		if err := json.Unmarshal([]byte(stored.Settings), out); err != nil {
			t.Fatalf("stored settings do not parse: %v", err)
		}
		return out
	}

	got := read()
	// Modes: the UNION, which is what the listener already accepted. bob gains
	// classic and alice gains tls; that granularity is what is being removed.
	if !got.ModeClassic || got.ModeSecure || !got.ModeTls {
		t.Errorf("modes = classic:%v secure:%v tls:%v, want the union classic+tls",
			got.ModeClassic, got.ModeSecure, got.ModeTls)
	}
	// The first FakeTLS account's domain, which telemt already emulated for the whole
	// process; alice's is deliberately ignored because she has no tls mode.
	if got.TlsDomain != "www.cloudflare.com" {
		t.Errorf("tlsDomain = %q, want the first FakeTLS account's domain", got.TlsDomain)
	}
	// The MAX, the one real behaviour change: alice was capped at 2 and comes out at 7.
	if got.UserLimit == nil || *got.UserLimit != 7 {
		t.Errorf("userLimit = %v, want the max across accounts (7)", got.UserLimit)
	}

	// Client fields this service does not model must survive the rewrite: the merge
	// writes back the raw object, not a re-marshalled struct.
	var stored model.Inbound
	if err := db.Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored.Settings, "keep me") {
		t.Error("the rewrite dropped a client field it does not model (comment)")
	}

	// The ad tag stayed on bob and did NOT reach the inbound. Both halves matter:
	// seeding it upward would have flattened two customers' tags into one, and the
	// stored key is what the rendered config still reads.
	var lifted map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stored.Settings), &lifted); err != nil {
		t.Fatal(err)
	}
	if _, seeded := lifted["adtag"]; seeded {
		t.Error("the migration seeded an inbound-level adtag; the tag is per client")
	}
	if _, seeded := lifted["adtagEnable"]; seeded {
		t.Error("the migration seeded an inbound-level adtagEnable; the tag is per client")
	}
	if parsed, perr := s.parseSettings(&stored); perr != nil {
		t.Fatal(perr)
	} else if !s.anyAdtag(parsed) {
		t.Error("bob's ad tag did not survive the migration: the whole inbound would silently go back to Xray routing")
	}

	// Idempotent: GenerateAllConfigs calls this every 10 seconds off the traffic job,
	// so a second pass must not touch anything (and must not re-derive the union after
	// an operator narrows the modes).
	got.ModeTls = false
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(model.Inbound{}).Where("id = ?", inbound.Id).Update("settings", string(raw)).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatal(err)
	}
	if after := read(); after.ModeTls {
		t.Error("a second pass re-derived the modes from the clients, undoing an operator edit")
	}
}

// An inbound with no accounts (or none holding a mode) must not migrate to "no modes":
// that config grants everything. It falls back to the fresh-inbound default instead.
func TestMtprotoLiftEmptyInboundGetsTheFreshDefaults(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	s := &MtprotoService{}

	inbound := &model.Inbound{UserId: 1, Tag: "inbound-9444", Port: 9444, Protocol: model.MTPROTO,
		Enable: true, Settings: `{"clients":[]}`}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatalf("LiftClientSettingsToInbound: %v", err)
	}

	var stored model.Inbound
	if err := db.Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	got := &mtprotoSettings{}
	if err := json.Unmarshal([]byte(stored.Settings), got); err != nil {
		t.Fatal(err)
	}
	if !got.ModeClassic || !got.ModeSecure || !got.ModeTls {
		t.Errorf("modes = %v/%v/%v, want all three on (the fresh-inbound default)",
			got.ModeClassic, got.ModeSecure, got.ModeTls)
	}
	if got.TlsDomain != "www.google.com" {
		t.Errorf("tlsDomain = %q, want the default", got.TlsDomain)
	}
	if got.UserLimit == nil || *got.UserLimit != 10 {
		t.Errorf("userLimit = %v, want an explicit 10 (the fresh-inbound default) for an empty inbound", got.UserLimit)
	}
}

// Accounts that predate the userLimit field resolved to ONE device each
// (effectiveUserLimit(nil)), so the lifted value has to be an explicit 1. Writing 0
// would read as "no limit" and quietly widen every legacy inbound to 16 devices.
func TestMtprotoLiftKeepsTheLegacySingleDeviceCap(t *testing.T) {
	newInboundDB(t)
	db := database.GetDB()
	s := &MtprotoService{}

	inbound := &model.Inbound{UserId: 1, Tag: "inbound-9445", Port: 9445, Protocol: model.MTPROTO,
		Enable: true, Settings: `{"clients":[{"id":"a","email":"a","secret":"00112233445566778899aabbccddeeff","enable":true,"modeSecure":true}]}`}
	if err := db.Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatalf("LiftClientSettingsToInbound: %v", err)
	}

	var stored model.Inbound
	if err := db.Where("id = ?", inbound.Id).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	got := &mtprotoSettings{}
	if err := json.Unmarshal([]byte(stored.Settings), got); err != nil {
		t.Fatal(err)
	}
	if got.UserLimit == nil || *got.UserLimit != 1 {
		t.Errorf("userLimit = %v, want an explicit 1 (what an absent per-client value meant)", got.UserLimit)
	}
	if effectiveUserLimit(got.UserLimit) != 1 {
		t.Errorf("effective device cap = %d, want 1", effectiveUserLimit(got.UserLimit))
	}
}

// The mode guard is what makes the QR gate and the daemon guard reachable states
// rather than defensive noise: an inbound cannot be SAVED with every mode off.
func TestValidateMtprotoRefusesAnInboundWithNoMode(t *testing.T) {
	err := ValidateProtocolSettings(model.MTPROTO,
		`{"modeClassic":false,"modeSecure":false,"modeTls":false,"clients":[]}`)
	if err == nil {
		t.Fatal("an inbound with every connection mode off was accepted")
	}
	if err := ValidateProtocolSettings(model.MTPROTO,
		`{"modeClassic":false,"modeSecure":true,"modeTls":false,"clients":[]}`); err != nil {
		t.Fatalf("one mode on was refused: %v", err)
	}
	// An old API body names none of the three. FillSettingsDefaults turns that into an
	// all-on inbound on the add path, so judging its absence here would refuse a body
	// that still works today.
	if err := ValidateProtocolSettings(model.MTPROTO, `{"clients":[]}`); err != nil {
		t.Fatalf("a body with no mode keys at all was refused: %v", err)
	}
	// The device cap is bounded like every other protocol's.
	if err := ValidateProtocolSettings(model.MTPROTO,
		`{"modeSecure":true,"userLimit":65,"clients":[]}`); err == nil {
		t.Error("userLimit 65 was accepted (max is 64)")
	}
}
