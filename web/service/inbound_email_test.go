package service

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/xray"
	"github.com/op/go-logging"
)

// The mutation paths log unconditionally, and logger.Debug dereferences a package
// global that is nil until InitLogger runs.
var emailTestLoggerOnce sync.Once

// newInboundDB gives the sqlite harness admin_test.go uses: InboundService reaches
// database.GetDB() directly, so there is nothing to inject.
func newInboundDB(t *testing.T) *InboundService {
	t.Helper()
	emailTestLoggerOnce.Do(func() { logger.InitLogger(logging.ERROR) })
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	// The client paths push changes to the live Xray over gRPC, reading the port off
	// this package global, which panics while nil. A never-started process reports
	// port 0, which XrayAPI.Init refuses before it dials, so the paths below run their
	// DB half and skip the gRPC half. Clients are seeded disabled for the same reason:
	// the AddUser/RemoveUser calls are guarded by the client's own enable flag.
	orig := p
	p = xray.NewProcess(&xray.Config{})
	t.Cleanup(func() { p = orig })
	return &InboundService{}
}

func testClient(email string) map[string]any {
	return map[string]any{
		"id":       uuid.NewString(),
		"email":    email,
		"password": "pw-" + email,
		"enable":   false,
	}
}

func clientSettings(clients ...map[string]any) string {
	bs, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		panic(err)
	}
	return string(bs)
}

// seedInbound writes a row directly, so a fixture never has to satisfy AddInbound's
// unrelated per-protocol validation.
func seedInbound(t *testing.T, port int, protocol model.Protocol, emails ...string) *model.Inbound {
	t.Helper()
	clients := make([]map[string]any, 0, len(emails))
	for _, email := range emails {
		clients = append(clients, testClient(email))
	}
	inbound := &model.Inbound{
		UserId:   1,
		Tag:      fmt.Sprintf("inbound-%d", port),
		Port:     port,
		Protocol: protocol,
		Enable:   false,
		Settings: clientSettings(clients...),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound on port %d: %v", port, err)
	}
	return inbound
}

func clientIdOf(t *testing.T, s *InboundService, inbound *model.Inbound, email string) string {
	t.Helper()
	reloaded, err := s.GetInbound(inbound.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	clients, err := s.GetClients(reloaded)
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	for _, c := range clients {
		if sameEmail(c.Email, email) {
			return c.ID
		}
	}
	t.Fatalf("no client %q in inbound %d", email, inbound.Id)
	return ""
}

func emailsInSettings(t *testing.T, s *InboundService, inboundId int) []string {
	t.Helper()
	inbound, err := s.GetInbound(inboundId)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	clients, err := s.GetClients(inbound)
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	out := make([]string, 0, len(clients))
	for _, c := range clients {
		out = append(out, c.Email)
	}
	return out
}

// A client's email is the GLOBAL account identity: it is the unique key of
// client_traffics, the name RADIUS authenticates and the selector the routing rules
// are keyed on. So every path that can write one must refuse a duplicate, whatever
// its spelling and whichever inbound it lands in. The matrix is (spelling of an
// email that is really "bob") x (path that tries to write it); "bob" always lives in
// a DIFFERENT inbound than the one being mutated, which is the global part.
func TestDuplicateEmailRejectedOnEveryMutationPath(t *testing.T) {
	spellings := []struct{ name, email string }{
		{"exact", "bob"},
		{"case folded", "BOB"},
		{"mixed case", "BoB"},
		{"trailing whitespace", "bob "},
		{"leading whitespace", " bob"},
		{"surrounding whitespace", "  Bob  "},
	}
	paths := []struct {
		name string
		// targetProtocol is the inbound the path mutates. UpdateInbound pushes a
		// non-VPN inbound to the live Xray unconditionally, which a unit test has no
		// gRPC server for: give it a VPN protocol so that a REGRESSION here reports a
		// plain "duplicate accepted" instead of a nil-client panic that takes the rest
		// of the matrix down with it.
		targetProtocol model.Protocol
		try            func(s *InboundService, target *model.Inbound, email string) error
	}{
		{"AddInbound", model.VMESS, func(s *InboundService, target *model.Inbound, email string) error {
			_, _, err := s.AddInbound(&model.Inbound{
				UserId: 1, Tag: "inbound-10099", Port: 10099, Protocol: model.VMESS,
				Settings: clientSettings(testClient(email)),
			})
			return err
		}},
		{"AddInboundClient", model.VMESS, func(s *InboundService, target *model.Inbound, email string) error {
			_, err := s.AddInboundClient(&model.Inbound{
				Id: target.Id, Settings: clientSettings(testClient(email)),
			})
			return err
		}},
		// The hole this suite was written for: UpdateInbound checked the port and
		// nothing else, so an edit could hand one account's email to another inbound.
		{"UpdateInbound", model.PPTP, func(s *InboundService, target *model.Inbound, email string) error {
			updated := *target
			updated.Settings = clientSettings(testClient(email))
			_, _, err := s.UpdateInbound(&updated)
			return err
		}},
		{"UpdateInboundClient", model.VMESS, func(s *InboundService, target *model.Inbound, email string) error {
			id := clientIdOf(t, s, target, "carol")
			renamed := testClient(email)
			renamed["id"] = id
			_, err := s.UpdateInboundClient(&model.Inbound{
				Id: target.Id, Settings: clientSettings(renamed),
			}, id)
			return err
		}},
	}

	for _, path := range paths {
		for _, spelling := range spellings {
			t.Run(path.name+"/"+spelling.name, func(t *testing.T) {
				s := newInboundDB(t)
				seedInbound(t, 10001, model.VMESS, "bob")
				target := seedInbound(t, 10002, path.targetProtocol, "carol")

				if err := path.try(s, target, spelling.email); err == nil {
					t.Fatalf("%s accepted %q while %q already exists in another inbound; "+
						"email identity is global and case- and whitespace-insensitive",
						path.name, spelling.email, "bob")
				}
			})
		}
	}
}

// The collision does not have to be in another inbound, nor even already persisted:
// a single batch carrying the same identity twice is just as broken.
func TestDuplicateEmailRejectedWithinOneInbound(t *testing.T) {
	tests := []struct {
		name  string
		try   func(s *InboundService, target *model.Inbound) error
		email string
	}{
		{"AddInboundClient onto its own inbound", func(s *InboundService, target *model.Inbound) error {
			_, err := s.AddInboundClient(&model.Inbound{
				Id: target.Id, Settings: clientSettings(testClient("BOB")),
			})
			return err
		}, "BOB"},
		{"AddInbound with a batch colliding with itself", func(s *InboundService, target *model.Inbound) error {
			_, _, err := s.AddInbound(&model.Inbound{
				UserId: 1, Tag: "inbound-10098", Port: 10098, Protocol: model.VMESS,
				Settings: clientSettings(testClient("dave"), testClient("DAVE ")),
			})
			return err
		}, "dave"},
		{"UpdateInbound with a batch colliding with itself", func(s *InboundService, target *model.Inbound) error {
			updated := *target
			updated.Settings = clientSettings(testClient("dave"), testClient("DAVE "))
			_, _, err := s.UpdateInbound(&updated)
			return err
		}, "dave"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newInboundDB(t)
			// A VPN protocol so a regression in UpdateInbound fails the assertion
			// rather than panicking on the live-Xray push.
			target := seedInbound(t, 10001, model.PPTP, "bob")

			if err := tt.try(s, target); err == nil {
				t.Fatalf("a duplicate of %q within one inbound was accepted", tt.email)
			}
		})
	}
}

// The regression this suite exists to pin. The rename guard compared with != while
// the duplicate check folds case, so "Bob" -> "bob" read as a change of identity,
// ran the global check, matched the client's OWN persisted row and was rejected as a
// duplicate of itself. Whitespace-only edits failed the same way.
func TestUpdateInboundClientSelfRenameSucceeds(t *testing.T) {
	tests := []struct {
		name      string
		from, to  string
		wantEmail string
	}{
		{"case-only rename", "Bob", "bob", "bob"},
		{"case-only rename upward", "bob", "BOB", "BOB"},
		{"identical email", "Bob", "Bob", "Bob"},
		{"whitespace-only edit is normalized away", "Bob", "  Bob  ", "Bob"},
		{"case and whitespace together", "Bob", " bob ", "bob"},
		{"genuine rename to a free email", "Bob", "robert", "robert"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newInboundDB(t)
			// A neighbour that must not be mistaken for the collision.
			seedInbound(t, 10001, model.VMESS, "alice")
			target := seedInbound(t, 10002, model.VMESS, tt.from)

			id := clientIdOf(t, s, target, tt.from)
			renamed := testClient(tt.to)
			renamed["id"] = id
			if _, err := s.UpdateInboundClient(&model.Inbound{
				Id: target.Id, Settings: clientSettings(renamed),
			}, id); err != nil {
				t.Fatalf("renaming %q to %q must not collide with the client's own row: %v",
					tt.from, tt.to, err)
			}

			got := emailsInSettings(t, s, target.Id)
			if len(got) != 1 || got[0] != tt.wantEmail {
				t.Errorf("stored emails = %q; want exactly [%q]", got, tt.wantEmail)
			}
		})
	}
}

// The other half of the UpdateInbound check: an inbound's own persisted row is not a
// competitor. Without the ignore-id the new check would reject every ordinary edit,
// because each client it KEEPS collides with itself.
func TestUpdateInboundKeepsItsOwnClients(t *testing.T) {
	s := newInboundDB(t)
	seedInbound(t, 10001, model.VMESS, "alice")
	// A VPN protocol: UpdateInbound pushes a non-VPN inbound to the live Xray
	// unconditionally, which a unit test has no gRPC server for.
	target := seedInbound(t, 10002, model.PPTP, "bob", "carol")

	updated := *target
	updated.Remark = "edited"
	// The same clients, re-posted verbatim, which is what the panel does on any edit.
	updated.Settings = clientSettings(testClient("bob"), testClient("carol"))

	if _, _, err := s.UpdateInbound(&updated); err != nil {
		t.Fatalf("re-saving an inbound with its own clients must succeed: %v", err)
	}

	got := emailsInSettings(t, s, target.Id)
	if len(got) != 2 {
		t.Fatalf("stored emails = %q; want 2", got)
	}
	// And a client added elsewhere is still caught afterwards.
	if _, err := s.AddInboundClient(&model.Inbound{
		Id: target.Id, Settings: clientSettings(testClient("alice")),
	}); err == nil {
		t.Error("the exclusion must not survive past the update it was for")
	}
}

// Normalizing on WRITE, not merely at compare time. client_traffics.email is the
// unique index, so if "bob " reached the DB the index would happily hold it beside
// "bob" and the invariant would be lost in the one place that is meant to be the
// last line of defense.
func TestClientEmailIsTrimmedBeforeItIsStored(t *testing.T) {
	tests := []struct {
		name string
		// try returns the id of the inbound whose stored settings should be checked.
		try  func(s *InboundService) int
		want string
	}{
		{"AddInbound", func(s *InboundService) int {
			added, _, err := s.AddInbound(&model.Inbound{
				UserId: 1, Tag: "inbound-10003", Port: 10003, Protocol: model.VMESS,
				Settings: clientSettings(testClient("  dave  ")),
			})
			if err != nil {
				t.Fatalf("AddInbound: %v", err)
			}
			return added.Id
		}, "dave"},
		{"AddInboundClient", func(s *InboundService) int {
			target := seedInbound(t, 10004, model.VMESS)
			if _, err := s.AddInboundClient(&model.Inbound{
				Id: target.Id, Settings: clientSettings(testClient("\tdave\n")),
			}); err != nil {
				t.Fatalf("AddInboundClient: %v", err)
			}
			return target.Id
		}, "dave"},
		{"UpdateInbound", func(s *InboundService) int {
			target := seedInbound(t, 10005, model.PPTP, "dave")
			updated := *target
			updated.Settings = clientSettings(testClient(" dave "))
			if _, _, err := s.UpdateInbound(&updated); err != nil {
				t.Fatalf("UpdateInbound: %v", err)
			}
			return target.Id
		}, "dave"},
		{"UpdateInboundClient", func(s *InboundService) int {
			target := seedInbound(t, 10006, model.VMESS, "carol")
			id := clientIdOf(t, s, target, "carol")
			renamed := testClient(" dave ")
			renamed["id"] = id
			if _, err := s.UpdateInboundClient(&model.Inbound{
				Id: target.Id, Settings: clientSettings(renamed),
			}, id); err != nil {
				t.Fatalf("UpdateInboundClient: %v", err)
			}
			return target.Id
		}, "dave"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newInboundDB(t)
			inboundId := tt.try(s)

			for _, email := range emailsInSettings(t, s, inboundId) {
				if email != strings.TrimSpace(email) {
					t.Errorf("settings stored %q untrimmed; the unique index would accept it "+
						"beside %q as a second account", email, strings.TrimSpace(email))
				}
			}
			// The settings JSON is the source the daemons and RADIUS read, but
			// client_traffics is what the index guards. Both must carry the same key.
			var stored []string
			if err := database.GetDB().Model(xray.ClientTraffic{}).
				Where("inbound_id = ?", inboundId).Pluck("email", &stored).Error; err != nil {
				t.Fatalf("read client_traffics: %v", err)
			}
			for _, email := range stored {
				if email != strings.TrimSpace(email) {
					t.Errorf("client_traffics stored %q untrimmed", email)
				}
			}
		})
	}
}

// The seam the UpdateInbound fix turns on, tested directly: the same clients are a
// collision against the rest of the DB and NOT against the row they already occupy.
func TestCheckEmailsExistExcludingInbound(t *testing.T) {
	s := newInboundDB(t)
	owner := seedInbound(t, 10001, model.VMESS, "bob")
	seedInbound(t, 10002, model.VMESS, "carol")

	bob := []model.Client{{Email: "bob"}}

	if got, err := s.checkEmailsExistExcludingInbound(bob, 0); err != nil || got == "" {
		t.Errorf("excluding nothing: got (%q, %v); want bob reported as taken", got, err)
	}
	if got, err := s.checkEmailsExistExcludingInbound(bob, owner.Id); err != nil || got != "" {
		t.Errorf("excluding bob's own inbound: got (%q, %v); want no collision", got, err)
	}
	// Excluding an unrelated inbound must not excuse the collision.
	if got, err := s.checkEmailsExistExcludingInbound(bob, 10002); err != nil || got == "" {
		t.Errorf("excluding an unrelated inbound: got (%q, %v); want bob still taken", got, err)
	}
	// Ids are AUTOINCREMENT from 1, so 0 is the sentinel meaning "exclude nothing".
	all, err := s.getAllEmailsExcludingInbound(0)
	if err != nil {
		t.Fatalf("getAllEmailsExcludingInbound: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("getAllEmailsExcludingInbound(0) = %q; want both emails", all)
	}
	// An empty email is not an identity and must never count as a collision.
	if got, _ := s.checkEmailsExistExcludingInbound([]model.Client{{Email: ""}, {Email: "  "}}, 0); got != "" {
		t.Errorf("blank emails reported as duplicate: %q", got)
	}
}

func TestSameEmail(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"bob", "bob", true},
		{"Bob", "bob", true},
		{"BOB", "bob", true},
		{"bob ", "bob", true},
		{" Bob\t", "bob", true},
		{"bob", "robert", false},
		{"bob", "bobb", false},
		{"", "", true},
		{"", "bob", false},
		// Trimming is edge-only: identity is not whitespace-free, just whitespace-
		// insensitive at the ends, so an inner space still makes a distinct account.
		{"b ob", "bob", false},
	}
	for _, tt := range tests {
		if got := sameEmail(tt.a, tt.b); got != tt.want {
			t.Errorf("sameEmail(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
