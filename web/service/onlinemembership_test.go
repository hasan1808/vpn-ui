package service

import (
	"sort"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/xray"
)

// Per-inbound liveness.
//
// The bug these pin: online was a list of EMAILS, so the Clients page had one
// answer for a whole account and repeated it against every inbound serving it. An
// account on ssh and l2tp connecting over ssh alone showed both as live, which is
// precisely the question the expander exists to answer.

func onlinePairs(t *testing.T, svc *InboundService) []string {
	t.Helper()
	got := append([]string(nil), svc.GetOnlineMemberships()...)
	sort.Strings(got)
	return got
}

// A tick carrying one record per inbound lights each of them on its own.
func TestOnlineMembershipsNameTheirInbound(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "wherefrom@example.com"
	openvpn, ikev2 := seedTwoInboundAccount(t, svc, email)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(nil, []*xray.ClientTraffic{
		{InboundId: openvpn.Id, Email: email, Up: 0, Down: 2 * mb},
	})
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	got := onlinePairs(t, inbounds)
	want := onlineMembershipKey(openvpn.Id, email)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("online memberships = %v; want exactly [%s]. The ikev2 membership moved "+
			"no bytes this tick and must not be reported live just because the account is.",
			got, want)
	}
	if strings.Contains(strings.Join(got, ","), onlineMembershipKey(ikev2.Id, email)) {
		t.Error("the ikev2 membership is marked live on the strength of the openvpn session")
	}

	// The account-wide list is unchanged: it still answers "is this customer
	// connected", which the row lamp and the dashboard count both need.
	if online := inbounds.GetOnlineClients(); len(online) != 1 || online[0] != email {
		t.Errorf("online clients = %v; want [%s]", online, email)
	}
}

// A record whose source inbound the collector could not name is filed under inbound
// 0 rather than dropped or guessed at. That is every Xray-native protocol: the
// core's per-user stat is "user>>><email>>>>traffic" with no inbound in it.
func TestOnlineMembershipsFileUnknownSourceUnderZero(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "unknownsource@example.com"
	openvpn, _ := seedTwoInboundAccount(t, svc, email)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(nil, []*xray.ClientTraffic{
		{InboundId: openvpn.Id, Email: email, Up: 0, Down: 1 * mb},
		{InboundId: 0, Email: email, Up: 0, Down: 3 * mb},
	})
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	got := onlinePairs(t, inbounds)
	want := []string{onlineMembershipKey(0, email), onlineMembershipKey(openvpn.Id, email)}
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("online memberships = %v; want %v. Inbound 0 is a meaning, not a miss: "+
			"it is what lets the page say \"live on one of this account's Xray inbounds\" "+
			"without naming one it was never told about.", got, want)
	}
}

// A record that moved nothing is not a session. Otherwise every account the tick
// happens to carry a zero row for lights up on that inbound.
func TestOnlineMembershipsIgnoreZeroDeltas(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "idle@example.com"
	openvpn, ikev2 := seedTwoInboundAccount(t, svc, email)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(nil, []*xray.ClientTraffic{
		{InboundId: openvpn.Id, Email: email, Up: 0, Down: 4 * mb},
		{InboundId: ikev2.Id, Email: email, Up: 0, Down: 0},
	})
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	got := onlinePairs(t, inbounds)
	if len(got) != 1 || got[0] != onlineMembershipKey(openvpn.Id, email) {
		t.Errorf("online memberships = %v; want only the openvpn pair", got)
	}
}

// A tick with nothing in it clears the previous one, or the last tick that DID see
// traffic keeps every membership it lit showing live until the panel restarts.
func TestOnlineMembershipsClearOnAnEmptyTick(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "wentaway@example.com"
	openvpn, _ := seedTwoInboundAccount(t, svc, email)

	inbounds := &InboundService{}
	err, _, _, _, _ := inbounds.AddTraffic(nil, []*xray.ClientTraffic{
		{InboundId: openvpn.Id, Email: email, Up: 0, Down: 2 * mb},
	})
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}
	if len(onlinePairs(t, inbounds)) != 1 {
		t.Fatal("the first tick did not record the session")
	}

	err, _, _, _, _ = inbounds.AddTraffic(nil, nil)
	if err != nil {
		t.Fatalf("AddTraffic (empty): %v", err)
	}
	if got := onlinePairs(t, inbounds); len(got) != 0 {
		t.Errorf("online memberships = %v after an empty tick; want none", got)
	}
}

// Identity is matched case-insensitively everywhere else in this panel, and the
// collected record carries whatever spelling the daemon reported. A pair the page
// cannot match against the account it belongs to is a pair that lights nothing.
func TestOnlineMembershipsNormaliseTheEmail(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "MixedCase@Example.com"

	openvpn := seedInboundWithClients(t, model.OPENVPN, 47701, []map[string]any{
		{"id": "mixed-login", "email": email, "enable": true, "totalGB": float64(0)},
	})
	svc.MigrationAccounts()
	account, err := svc.GetAccountByEmail(email)
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	account.VpnUsername = "mixed-login"
	account.Password = "mixed-pw"
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save account: %v", err)
	}
	if _, err := svc.ApplyMemberships(email, []int{openvpn.Id}, nil, true); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}
	seedAccountTraffic(t, email, openvpn.Id)

	inbounds := &InboundService{}
	err, _, _, _, _ = inbounds.AddTraffic(nil, []*xray.ClientTraffic{
		{InboundId: openvpn.Id, Email: email, Up: 0, Down: 1 * mb},
	})
	if err != nil {
		t.Fatalf("AddTraffic: %v", err)
	}

	got := onlinePairs(t, inbounds)
	want := onlineMembershipKey(openvpn.Id, "mixedcase@example.com")
	if len(got) != 1 || got[0] != want {
		t.Errorf("online memberships = %v; want [%s] with the email normalised", got, want)
	}
}
