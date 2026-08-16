package service

import (
	"encoding/json"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// The VPN protocols joined the subscription after their accounts already existed, so
// their stored clients can carry no subId at all, and an account without one has no
// subscription link: the sub endpoints cannot find it and the panel shows it nothing.
// MigrationSubIds closes that gap on startup. What these cover is that it closes it
// for exactly those accounts and touches nothing else.

func seedInboundWithClients(t *testing.T, protocol model.Protocol, port int, clients []map[string]any) *model.Inbound {
	t.Helper()
	settings, err := json.Marshal(map[string]any{"clients": clients})
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	inbound := &model.Inbound{
		UserId: 1, Tag: string(protocol) + "-inbound", Port: port,
		Protocol: protocol, Enable: true, Settings: string(settings),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	return inbound
}

// readClients returns the stored clients of an inbound as raw maps, so a test sees the
// JSON as the sub service reads it rather than as a struct with defaults filled in.
func readClients(t *testing.T, id int) []map[string]any {
	t.Helper()
	var inbound model.Inbound
	if err := database.GetDB().Model(model.Inbound{}).Where("id = ?", id).First(&inbound).Error; err != nil {
		t.Fatalf("read inbound %d: %v", id, err)
	}
	var settings struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	return settings.Clients
}

func subIdOf(t *testing.T, c map[string]any) string {
	t.Helper()
	s, _ := c["subId"].(string)
	return s
}

// The backfill is per client: two accounts missing a subId get two different ones, so
// neither inherits the other's subscription page.
func TestMigrationSubIdsFillsMissingPerClient(t *testing.T) {
	svc := newInboundDB(t)
	inbound := seedInboundWithClients(t, model.L2TP, 41101, []map[string]any{
		{"email": "first", "password": "p1", "enable": true},
		{"email": "second", "password": "p2", "enable": true, "subId": ""},
	})

	svc.MigrationSubIds()

	clients := readClients(t, inbound.Id)
	if len(clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(clients))
	}
	first, second := subIdOf(t, clients[0]), subIdOf(t, clients[1])
	if len(first) != 16 || len(second) != 16 {
		t.Fatalf("want two 16-char subIds, got %q and %q", first, second)
	}
	if first == second {
		t.Fatalf("both clients were given the same subId %q", first)
	}
	// The rest of the client must survive the rewrite: settings are spliced through a
	// generic map, so a dropped field here would be a silently broken account.
	if clients[0]["password"] != "p1" || clients[0]["email"] != "first" {
		t.Fatalf("client fields lost in the rewrite: %+v", clients[0])
	}
}

// An existing subId is an admin's choice (clients that share one share a subscription),
// so the backfill must never reassign it, and a second pass must be a no-op.
func TestMigrationSubIdsKeepsExistingAndIsIdempotent(t *testing.T) {
	svc := newInboundDB(t)
	inbound := seedInboundWithClients(t, model.OPENVPN, 41102, []map[string]any{
		{"email": "kept", "subId": "shared-sub-id"},
		{"email": "minted"},
		// No email: no account identity, so there is nothing to report usage for.
		{"email": ""},
	})

	svc.MigrationSubIds()
	first := readClients(t, inbound.Id)
	if got := subIdOf(t, first[0]); got != "shared-sub-id" {
		t.Fatalf("existing subId was rewritten to %q", got)
	}
	if got := subIdOf(t, first[2]); got != "" {
		t.Fatalf("email-less client was given subId %q", got)
	}
	minted := subIdOf(t, first[1])
	if len(minted) != 16 {
		t.Fatalf("want a minted 16-char subId, got %q", minted)
	}

	svc.MigrationSubIds()
	second := readClients(t, inbound.Id)
	if got := subIdOf(t, second[1]); got != minted {
		t.Fatalf("second pass reminted the subId: %q -> %q", minted, got)
	}
}

// Scope guard: an Xray client has been given a subId at creation since long before
// this pass existed, so an empty one there means the admin cleared the field.
func TestMigrationSubIdsSkipsXrayProtocols(t *testing.T) {
	svc := newInboundDB(t)
	inbound := seedInboundWithClients(t, model.VMESS, 41103, []map[string]any{
		{"email": "cleared-on-purpose", "subId": ""},
	})

	svc.MigrationSubIds()

	if got := subIdOf(t, readClients(t, inbound.Id)[0]); got != "" {
		t.Fatalf("vmess client was backfilled with subId %q", got)
	}
}
