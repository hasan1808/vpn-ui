package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func naiveClient(email, username, password string) map[string]any {
	c := map[string]any{"email": email, "password": password, "enable": false}
	if username != "" {
		c["username"] = username
	}
	return c
}

// The Basic-auth username the core will match. Everything else in this file is about
// keeping the panel's idea of it identical to the core's, because the core degrades a
// duplicate with a warning rather than an error (an error out of Build() makes Xray
// refuse the WHOLE config), so nothing downstream reports the collision.
func TestNaiveAuthUsernameFallsBackToTheEmail(t *testing.T) {
	cases := []struct {
		client model.Client
		want   string
	}{
		{model.Client{Email: "alice", Username: "bob"}, "bob"},
		{model.Client{Email: "alice"}, "alice"},
		{model.Client{Email: "alice", Username: ""}, "alice"},
		// NOT trimmed: the core tests the raw field for emptiness, and a panel that
		// resolved " " to the email here would validate one credential and hand out
		// another.
		{model.Client{Email: "alice", Username: " "}, " "},
	}
	for _, c := range cases {
		if got := naiveAuthUsername(c.client); got != c.want {
			t.Errorf("naiveAuthUsername(%+v) = %q, want %q", c.client, got, c.want)
		}
	}
}

func TestFirstNaiveUsernameFault(t *testing.T) {
	cases := []struct {
		name       string
		clients    []model.Client
		wantClient string
		wantReason string
	}{
		{
			name: "all distinct",
			clients: []model.Client{
				{Email: "a", Username: "one"},
				{Email: "b", Username: "two"},
				{Email: "c"},
			},
		},
		{
			name: "two explicit usernames collide",
			clients: []model.Client{
				{Email: "a", Username: "same"},
				{Email: "b", Username: "same"},
			},
			wantClient: "b", wantReason: "duplicate",
		},
		{
			// The collision the resolved value catches and the raw field does not: a
			// username-less account authenticates as its email, so "bob" here is one
			// credential claimed twice.
			name: "an explicit username collides with another account's email",
			clients: []model.Client{
				{Email: "bob"},
				{Email: "carol", Username: "bob"},
			},
			wantClient: "carol", wantReason: "duplicate",
		},
		{
			name: "a colon is unauthenticable",
			clients: []model.Client{
				{Email: "a", Username: "user:name"},
			},
			wantClient: "a", wantReason: "colon",
		},
		{
			// Empty is not a collision, it is the fallback: two accounts with no
			// username still differ, because their emails do.
			name: "several accounts with no username",
			clients: []model.Client{
				{Email: "a"}, {Email: "b"}, {Email: "c"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotClient, gotReason := firstNaiveUsernameFault(c.clients)
			if gotClient != c.wantClient {
				t.Errorf("client = %q, want %q", gotClient, c.wantClient)
			}
			if c.wantReason == "" {
				if gotReason != "" {
					t.Errorf("reason = %q, want none", gotReason)
				}
				return
			}
			if !strings.Contains(gotReason, c.wantReason) {
				t.Errorf("reason = %q, want it to mention %q", gotReason, c.wantReason)
			}
			// A live credential must never reach an error string, a log line or the UI.
			for _, client := range c.clients {
				if client.Username != "" && strings.Contains(gotReason, client.Username) {
					t.Errorf("reason %q leaks a username", gotReason)
				}
			}
		})
	}
}

// The identity trap. naive is keyed on the PASSWORD, and it has to stay that way: an
// account created before the username field has none, so keying on the username would
// give it an empty identity, the modal would POST to /updateClient/ with nothing to
// match, and the edit would come back "empty client ID".
func TestNaiveClientsAreStillAddressedByPassword(t *testing.T) {
	if got := clientIdentityKey(model.NAIVE); got != "password" {
		t.Fatalf("clientIdentityKey(naive) = %q, want %q", got, "password")
	}
	withUsername := model.Client{Email: "alice", Username: "bob", Password: "pw"}
	if got := clientIdentity(model.NAIVE, withUsername); got != "pw" {
		t.Errorf("clientIdentity with a username = %q, want the password", got)
	}
	legacy := model.Client{Email: "alice", Password: "pw"}
	if got := clientIdentity(model.NAIVE, legacy); got != "pw" {
		t.Errorf("clientIdentity without a username = %q, want the password", got)
	}
}

// Editing a naive account must work whether or not it has a username, and must be able
// to ADD one to an account that had none: that is the upgrade path for every row
// already in the DB.
func TestUpdateNaiveClientCanAddAndKeepAUsername(t *testing.T) {
	for _, c := range []struct {
		name         string
		stored       map[string]any
		newUsername  string
		wantUsername string
	}{
		{"adds a username to a legacy account", naiveClient("alice", "", "pw-1"), "alice-login", "alice-login"},
		{"keeps an existing username", naiveClient("alice", "alice-login", "pw-1"), "alice-login", "alice-login"},
		{"clears a username back to the email fallback", naiveClient("alice", "alice-login", "pw-1"), "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newInboundDB(t)
			inbound := &model.Inbound{
				UserId: 1, Tag: "inbound-naive", Port: 14000, Protocol: model.NAIVE,
				Enable: false, Settings: clientSettings(c.stored),
			}
			if err := database.GetDB().Create(inbound).Error; err != nil {
				t.Fatalf("seed inbound: %v", err)
			}

			// What the modal puts in the URL: the password, unchanged by the edit.
			updated := naiveClient("alice", c.newUsername, "pw-1")
			payload := &model.Inbound{Id: inbound.Id, Settings: clientSettings(updated)}
			if _, err := s.UpdateInboundClient(payload, "pw-1"); err != nil {
				t.Fatalf("UpdateInboundClient: %v", err)
			}

			stored, err := s.GetInbound(inbound.Id)
			if err != nil {
				t.Fatalf("GetInbound: %v", err)
			}
			clients, err := s.GetClients(stored)
			if err != nil {
				t.Fatalf("GetClients: %v", err)
			}
			if len(clients) != 1 || clients[0].Username != c.wantUsername {
				t.Fatalf("username did not land: %s", stored.Settings)
			}
		})
	}
}

// The panel denies with HTTP 200 + success:false, so the refusal has to come back as an
// error from the service or nothing reports it at all.
func TestUpdateNaiveClientRejectsACollidingUsername(t *testing.T) {
	s := newInboundDB(t)
	inbound := &model.Inbound{
		UserId: 1, Tag: "inbound-naive-dup", Port: 14001, Protocol: model.NAIVE,
		Enable: false,
		Settings: clientSettings(
			naiveClient("alice", "taken", "pw-a"),
			naiveClient("bob", "", "pw-b"),
		),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}

	payload := &model.Inbound{Id: inbound.Id, Settings: clientSettings(naiveClient("bob", "taken", "pw-b"))}
	if _, err := s.UpdateInboundClient(payload, "pw-b"); err == nil {
		t.Fatal("a duplicate naive username was accepted")
	}

	// And a colon, which moves the Basic split and makes the account unauthenticable.
	payload = &model.Inbound{Id: inbound.Id, Settings: clientSettings(naiveClient("bob", "bo:b", "pw-b"))}
	if _, err := s.UpdateInboundClient(payload, "pw-b"); err == nil {
		t.Fatal("a naive username containing a colon was accepted")
	}

	// Neither refusal may have mutated anything.
	stored, err := s.GetInbound(inbound.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	var got struct {
		Clients []struct {
			Email    string `json:"email"`
			Username string `json:"username"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(stored.Settings), &got); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	if len(got.Clients) != 2 || got.Clients[1].Username != "" {
		t.Fatalf("a refused edit still landed: %s", stored.Settings)
	}
}

// Adding a client to a live inbound is measured against what the inbound ALREADY holds,
// not just the incoming batch: the core's account index is per-inbound.
func TestAddNaiveClientRejectsAUsernameAlreadyInTheInbound(t *testing.T) {
	s := newInboundDB(t)
	inbound := &model.Inbound{
		UserId: 1, Tag: "inbound-naive-add", Port: 14002, Protocol: model.NAIVE,
		Enable: false, Settings: clientSettings(naiveClient("alice", "taken", "pw-a")),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}

	payload := &model.Inbound{Id: inbound.Id, Settings: clientSettings(naiveClient("bob", "taken", "pw-b"))}
	if _, err := s.AddInboundClient(payload); err == nil {
		t.Fatal("a username already present in the inbound was accepted")
	}

	// A free one goes through, which is what proves the check is not simply refusing
	// every add.
	payload = &model.Inbound{Id: inbound.Id, Settings: clientSettings(naiveClient("bob", "free", "pw-b"))}
	if _, err := s.AddInboundClient(payload); err != nil {
		t.Fatalf("AddInboundClient with a free username: %v", err)
	}
}

// A copy carries the source client wholesale, so the username had to be cleared with
// the other credentials: an inherited one collides in the target inbound on arrival.
func TestCopiedNaiveClientDropsTheSourceUsername(t *testing.T) {
	s := &InboundService{}
	source := model.Client{Email: "src@example.com", Username: "src-login", Password: "src-pw"}
	target, err := s.buildTargetClientFromSource(source, model.NAIVE, "copy@example.com", "")
	if err != nil {
		t.Fatalf("buildTargetClientFromSource: %v", err)
	}
	if target.Username != "" {
		t.Errorf("copy inherited the source username %q", target.Username)
	}
	if got := naiveAuthUsername(target); got != "copy@example.com" {
		t.Errorf("copy authenticates as %q, want its own email", got)
	}
}
