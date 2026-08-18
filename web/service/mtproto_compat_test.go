package service

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// Compatibility with the shape MTProto settings had before the modes, the FakeTLS
// domain and the device cap moved from the clients onto the inbound.
//
// Two properties, and they are what make the move safe in both directions:
//
//   - An inbound in the OLD shape means exactly what the equivalent new one means, on
//     every path it can arrive by, whether or not the lift has run on it yet.
//   - The blob the panel writes keeps satisfying the PREVIOUS binary, so a rollback does
//     not strand the accounts created since the upgrade.
//
// See the compatibility block in mtproto.go. The lift's own seeding rules are pinned in
// mtproto_settings_test.go; these tests are about the paths, the mirror and the churn.

// mtprotoLegacyBlob is one inbound in the pre-move shape. alice holds classic+secure
// and a 4-device cap, bob holds FakeTLS with a domain and a 2-device cap, so the
// resolution exercises all three rules at once: the union, the first FakeTLS domain,
// and the largest cap.
const mtprotoLegacyBlob = `{"clients":[
	{"id":"alice","email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true,
	 "modeClassic":true,"modeSecure":true,"userLimit":4,"comment":"keep me"},
	{"id":"bob","email":"bob","secret":"ffeeddccbbaa99887766554433221100","enable":true,
	 "modeTls":true,"tlsDomain":"www.cloudflare.com","userLimit":2}
]}`

// mtprotoMigratedBlob is the same inbound already in the current shape: the union of
// the two accounts' modes, bob's FakeTLS domain, and the larger of the two caps.
const mtprotoMigratedBlob = `{"modeClassic":true,"modeSecure":true,"modeTls":true,
	"tlsDomain":"www.cloudflare.com","userLimit":4,"clients":[
	{"id":"alice","email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true,"comment":"keep me"},
	{"id":"bob","email":"bob","secret":"ffeeddccbbaa99887766554433221100","enable":true}
]}`

func mtprotoInboundFrom(settings string) *model.Inbound {
	return &model.Inbound{Id: 3, Port: 9443, Tag: "inbound-9443", Protocol: model.MTPROTO, Settings: settings}
}

// renderMtproto is the config telemt would be handed for one inbound.
func renderMtproto(t *testing.T, inbound *model.Inbound) string {
	t.Helper()
	s := &MtprotoService{}
	settings, err := s.parseSettings(inbound)
	if err != nil {
		t.Fatalf("parseSettings: %v", err)
	}
	return s.buildServerConfig(inbound, settings)
}

// The whole contract in one assertion: reading an inbound still in the old shape must
// produce the SAME telemt config as the equivalent new-shape one, with no lift in
// between. Anything less means the daemon's behaviour changes at the moment the lift
// happens to run, which is a background pass on a 10-second timer.
func TestMtprotoLegacyShapeRendersTheSameConfig(t *testing.T) {
	legacy := renderMtproto(t, mtprotoInboundFrom(mtprotoLegacyBlob))
	migrated := renderMtproto(t, mtprotoInboundFrom(mtprotoMigratedBlob))
	if legacy != migrated {
		t.Errorf("an un-lifted inbound renders a different config than the lifted one:\n--- legacy ---\n%s\n--- migrated ---\n%s",
			legacy, migrated)
	}
}

// The read-side fallback lives on mtprotoSettings itself, so no decoder can reach the
// wrong answer. Without it the modes come out all-false, which telemt reads as "no
// restriction" rather than "no modes" and startable() refuses to run at all.
func TestMtprotoParseResolvesLegacySettings(t *testing.T) {
	s := &MtprotoService{}
	settings, err := s.parseSettings(mtprotoInboundFrom(mtprotoLegacyBlob))
	if err != nil {
		t.Fatal(err)
	}
	if !settings.ModeClassic || !settings.ModeSecure || !settings.ModeTls {
		t.Errorf("modes = %v/%v/%v, want the union of the accounts' modes",
			settings.ModeClassic, settings.ModeSecure, settings.ModeTls)
	}
	if settings.TlsDomain != "www.cloudflare.com" {
		t.Errorf("tlsDomain = %q, want the first FakeTLS account's domain", settings.TlsDomain)
	}
	if settings.UserLimit == nil || *settings.UserLimit != 4 {
		t.Errorf("userLimit = %v, want the largest cap any account held (4)", settings.UserLimit)
	}
	if !s.startable(settings) {
		t.Error("a legacy inbound reported not startable: telemt would never be launched for it")
	}
}

// A mixed inbound: alice predates the move and carries the old keys, bob was added by a
// newer binary and carries none. bob must not drag the resolution down.
//
// Documented resolution: the union is alice's set (bob contributes nothing), and the cap
// is the largest EFFECTIVE one, where bob's absent value counts as the single device it
// has always meant, so alice's explicit 3 wins.
func TestMtprotoMixedClientsResolveTheDocumentedWay(t *testing.T) {
	mixed := `{"clients":[
		{"email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true,
		 "modeSecure":true,"userLimit":3},
		{"email":"bob","secret":"ffeeddccbbaa99887766554433221100","enable":true}
	]}`
	s := &MtprotoService{}
	settings, err := s.parseSettings(mtprotoInboundFrom(mixed))
	if err != nil {
		t.Fatal(err)
	}
	if settings.ModeClassic || !settings.ModeSecure || settings.ModeTls {
		t.Errorf("modes = %v/%v/%v, want only secure (the one mode any account held)",
			settings.ModeClassic, settings.ModeSecure, settings.ModeTls)
	}
	if settings.UserLimit == nil || *settings.UserLimit != 3 {
		t.Errorf("userLimit = %v, want 3: an absent per-client cap means one device, not no limit", settings.UserLimit)
	}
	// No account asked for FakeTLS, so there is no domain to preserve and the default
	// stands. It is never left empty: telemt models its fake certificate on a real one.
	if settings.TlsDomain != "www.google.com" {
		t.Errorf("tlsDomain = %q, want the default", settings.TlsDomain)
	}
}

// The API add path. FillSettingsDefaults would otherwise stamp the fresh-inbound values
// (all three modes on, no device cap) onto a body whose policy is on its clients, and
// the blob would then look already-migrated to every later reader: the values would be
// gone with nothing left to recover them from.
func TestMtprotoApiAddKeepsLegacyShapeValues(t *testing.T) {
	inbound := mtprotoInboundFrom(`{"clients":[
		{"id":"a","email":"a","secret":"00112233445566778899aabbccddeeff","enable":true,
		 "modeSecure":true,"tlsDomain":"ignored.example","userLimit":5}
	]}`)
	if err := NormalizeInboundSettings(inbound); err != nil {
		t.Fatalf("NormalizeInboundSettings: %v", err)
	}
	var got mtprotoSettings
	if err := json.Unmarshal([]byte(inbound.Settings), &got); err != nil {
		t.Fatal(err)
	}
	if got.ModeClassic || !got.ModeSecure || got.ModeTls {
		t.Errorf("modes = %v/%v/%v, want only secure: the defaults widened the caller's set",
			got.ModeClassic, got.ModeSecure, got.ModeTls)
	}
	if got.UserLimit == nil || *got.UserLimit != 5 {
		t.Errorf("userLimit = %v, want the caller's 5 rather than the default 10", got.UserLimit)
	}
	// The domain came off an account with no FakeTLS mode, which is exactly the one the
	// process was never emulating, so the default stands here too.
	if got.TlsDomain != "www.google.com" {
		t.Errorf("tlsDomain = %q, want the default", got.TlsDomain)
	}
	// And the result is a blob the validator accepts, since the add path judges the
	// filled body rather than the posted one.
	if err := ValidateProtocolSettings(model.MTPROTO, inbound.Settings); err != nil {
		t.Errorf("the normalized body no longer validates: %v", err)
	}
}

// A body already in the current shape must come through byte-identical: this runs on
// every add the panel makes, and a rewrite here would reorder keys on every inbound
// anyone creates.
func TestMtprotoApiAddLeavesTheCurrentShapeAlone(t *testing.T) {
	const body = `{"modeClassic":false,"modeSecure":true,"modeTls":false,"tlsDomain":"a.example","userLimit":2,"clients":[],"externalProxy":[]}`
	inbound := mtprotoInboundFrom(body)
	if err := NormalizeInboundSettings(inbound); err != nil {
		t.Fatalf("NormalizeInboundSettings: %v", err)
	}
	if inbound.Settings != body {
		t.Errorf("a current-shape body was rewritten:\n got=%s\nwant=%s", inbound.Settings, body)
	}
}

// seedMtprotoInbound puts one inbound into a fresh temp database.
func seedMtprotoInbound(t *testing.T, port int, settings string) *model.Inbound {
	t.Helper()
	inbound := &model.Inbound{UserId: 1, Tag: fmt.Sprintf("inbound-%d", port), Port: port,
		Protocol: model.MTPROTO, Enable: true, Settings: settings}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	return inbound
}

// storedInbound re-reads an inbound from the database.
func storedInbound(t *testing.T, id int) *model.Inbound {
	t.Helper()
	var out model.Inbound
	if err := database.GetDB().Where("id = ?", id).First(&out).Error; err != nil {
		t.Fatalf("re-read inbound %d: %v", id, err)
	}
	return &out
}

// A database that arrives ALREADY OLD: a restored backup, an imported foreign DB, or
// `vpn-ui migrate`. None of those goes through panel startup, and the reader's tolerance
// is not enough on its own, because the panel's inbound form posts back what it read.
func TestMtprotoImportPathLiftsLegacySettings(t *testing.T) {
	svc := newInboundDB(t)
	seeded := seedMtprotoInbound(t, 9451, mtprotoLegacyBlob)

	svc.MigrateDB() // the migrate / import / restore hook

	stored := storedInbound(t, seeded.Id)
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stored.Settings), &root); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"modeClassic", "modeSecure", "modeTls", "tlsDomain", "userLimit"} {
		if _, ok := root[key]; !ok {
			t.Fatalf("an imported legacy inbound still has no inbound-level %q after MigrateDB", key)
		}
	}
	// Same config as the equivalent already-migrated inbound, which is the property the
	// whole exercise is for. Port and tag are matched so only the settings can differ.
	stored.Id, stored.Port, stored.Tag = 3, 9443, "inbound-9443"
	if got, want := renderMtproto(t, stored), renderMtproto(t, mtprotoInboundFrom(mtprotoMigratedBlob)); got != want {
		t.Errorf("an imported legacy inbound renders a different config:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The lift and the mirror both run from GenerateAllConfigs, which the traffic job calls
// every 10 seconds, so they have to settle after one pass and stay settled. The
// generated config is the thing that must not churn: telemt watches its config file with
// inotify and reloads on any write, so a config that differs pass to pass would make it
// reload forever.
func TestMtprotoLiftAndMirrorAreIdempotent(t *testing.T) {
	newInboundDB(t)
	seeded := seedMtprotoInbound(t, 9452, mtprotoLegacyBlob)
	s := &MtprotoService{}

	pass := func() (settings, config string) {
		t.Helper()
		if err := s.LiftClientSettingsToInbound(); err != nil {
			t.Fatalf("lift: %v", err)
		}
		if err := s.MirrorInboundSettingsToClients(); err != nil {
			t.Fatalf("mirror: %v", err)
		}
		stored := storedInbound(t, seeded.Id)
		return stored.Settings, renderMtproto(t, stored)
	}

	settings1, config1 := pass()
	settings2, config2 := pass()
	settings3, config3 := pass()

	// The anti-churn property, and the one that actually costs something when it breaks.
	if config1 != config2 || config2 != config3 {
		t.Errorf("the generated config changed between passes; telemt would reload on every traffic tick:\n1: %s\n2: %s\n3: %s",
			config1, config2, config3)
	}
	// The stored blob settles too, so the passes stop writing to the database at all.
	if settings2 != settings1 {
		t.Errorf("the second pass rewrote the settings:\n1: %s\n2: %s", settings1, settings2)
	}
	if settings3 != settings2 {
		t.Errorf("the third pass rewrote the settings:\n2: %s\n3: %s", settings2, settings3)
	}
	// A no-op pass must also leave an operator's later narrowing alone, which is what the
	// key-presence test buys: re-deriving the union from the clients would undo the edit.
	narrowed := `{"modeClassic":false,"modeSecure":true,"modeTls":false,"tlsDomain":"www.cloudflare.com","userLimit":4,"clients":[]}`
	if err := database.GetDB().Model(model.Inbound{}).Where("id = ?", seeded.Id).
		Update("settings", narrowed).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.LiftClientSettingsToInbound(); err != nil {
		t.Fatal(err)
	}
	after, err := s.parseSettings(storedInbound(t, seeded.Id))
	if err != nil {
		t.Fatal(err)
	}
	if after.ModeClassic || after.ModeTls {
		t.Error("a later pass re-derived the modes from the clients, undoing an operator edit")
	}
}

// The downgrade mirror. The previous binary reads the modes, the domain and the cap only
// from the clients, and DROPS a client whose mode set is empty (it disappears from
// [access.users] entirely). So an account added after the upgrade, which carries none of
// those keys, would be unable to connect on a rollback with nothing in the log saying
// why. The mirror is what stops that.
func TestMtprotoMirrorSurvivesADowngrade(t *testing.T) {
	newInboundDB(t)
	seeded := seedMtprotoInbound(t, 9453, mtprotoMigratedBlob)
	db := database.GetDB()
	s := &MtprotoService{}

	// A client added after the upgrade: exactly what the panel's form posts, which is
	// email/secret/enable and no dead fields at all.
	withNewClient := `{"modeClassic":true,"modeSecure":true,"modeTls":true,
		"tlsDomain":"www.cloudflare.com","userLimit":4,"clients":[
		{"id":"alice","email":"alice","secret":"00112233445566778899aabbccddeeff","enable":true},
		{"id":"carol","email":"carol","secret":"aabbccddeeff00112233445566778899","enable":true}
	]}`
	if err := db.Model(model.Inbound{}).Where("id = ?", seeded.Id).Update("settings", withNewClient).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.MirrorInboundSettingsToClients(); err != nil {
		t.Fatalf("mirror: %v", err)
	}

	// Read the stored clients back through the PRE-MOVE struct, which is what the old
	// binary decodes them with.
	var stored struct {
		Clients []mtprotoLegacyClient `json:"clients"`
	}
	if err := json.Unmarshal([]byte(storedInbound(t, seeded.Id).Settings), &stored); err != nil {
		t.Fatal(err)
	}
	if len(stored.Clients) != 2 {
		t.Fatalf("got %d clients, want 2", len(stored.Clients))
	}
	for i, c := range stored.Clients {
		if !c.ModeClassic || !c.ModeSecure || !c.ModeTls {
			t.Errorf("client %d has modes %v/%v/%v: the old binary drops an account with an empty mode set",
				i, c.ModeClassic, c.ModeSecure, c.ModeTls)
		}
		if c.TlsDomain != "www.cloudflare.com" {
			t.Errorf("client %d has tlsDomain %q, want the inbound's domain", i, c.TlsDomain)
		}
		// The RAW cap, so an explicit 0 still means "no limit" over there and resolves
		// through the same effectiveUserLimit.
		if c.UserLimit == nil || *c.UserLimit != 4 {
			t.Errorf("client %d has userLimit %v, want the inbound's 4", i, c.UserLimit)
		}
	}

	// And the mirrored blob still means the same thing to THIS binary if the inbound-level
	// keys are ever lost again (an old binary's write, a partial API update): the union of
	// the mirrored modes is the inbound's set, and the largest mirrored cap is its cap. So
	// the round-trip through the old shape is lossless rather than merely survivable.
	legacyAgain := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(storedInbound(t, seeded.Id).Settings), &legacyAgain); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"modeClassic", "modeSecure", "modeTls", "tlsDomain", "userLimit"} {
		delete(legacyAgain, key)
	}
	stripped, err := json.Marshal(legacyAgain)
	if err != nil {
		t.Fatal(err)
	}
	policy := MtprotoInboundPolicyOf(string(stripped))
	if !policy.ModeClassic || !policy.ModeSecure || !policy.ModeTls {
		t.Errorf("re-resolving the mirrored blob lost modes: %v/%v/%v",
			policy.ModeClassic, policy.ModeSecure, policy.ModeTls)
	}
	if policy.TlsDomain != "www.cloudflare.com" {
		t.Errorf("re-resolving the mirrored blob gave tlsDomain %q", policy.TlsDomain)
	}
	if policy.UserLimit == nil || *policy.UserLimit != 4 {
		t.Errorf("re-resolving the mirrored blob gave userLimit %v", policy.UserLimit)
	}
}

// The mirror writes keys nothing here reads, so it must not move the generated config by
// a single byte: generateServerConfig compares against the file on disk and telemt
// reloads on any write.
func TestMtprotoMirrorDoesNotMoveTheGeneratedConfig(t *testing.T) {
	newInboundDB(t)
	seeded := seedMtprotoInbound(t, 9454, mtprotoMigratedBlob)
	before := renderMtproto(t, storedInbound(t, seeded.Id))

	s := &MtprotoService{}
	if err := s.MirrorInboundSettingsToClients(); err != nil {
		t.Fatalf("mirror: %v", err)
	}
	after := storedInbound(t, seeded.Id)
	if after.Settings == mtprotoMigratedBlob {
		t.Fatal("the mirror wrote nothing, so this test is not proving anything")
	}
	if got := renderMtproto(t, after); got != before {
		t.Errorf("the mirror changed the generated config:\n--- before ---\n%s\n--- after ---\n%s", before, got)
	}
}
