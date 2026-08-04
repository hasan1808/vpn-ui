package service

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// The three validators are pure functions, so they only exist if something calls
// them. They were written, tested and documented as enforced while being DEAD
// CODE: the only reference outside their own definitions was a comment. These
// pin the wiring, not the rules.

func TestAddInboundRejectsUnusableIdentities(t *testing.T) {
	cases := []struct {
		name     string
		protocol model.Protocol
		port     int
		settings string
		// control is the same client list with the offending value sanitized. It
		// must be ACCEPTED, or the case below proves nothing.
		control string
		wantIn  string
	}{
		{
			// chap-secrets and ocpasswd are line-oriented, so a newline appends a
			// record the operator never created.
			"newline in vpn username", model.L2TP, 26101,
			`{"clients":[{"id":"bob\ninjected ANY pw *","password":"pw","email":"a1","enable":false}]}`,
			`{"clients":[{"id":"bobinjected","password":"pw","email":"a1","enable":false}]}`,
			"control character",
		},
		{
			// The openvpn CCD block is written to a path ending in the username.
			// Exercised on ssh, which shares the rule and needs no certificate
			// (openvpn's cert guard runs first and would mask this).
			"path separator in vpn username", model.SSH, 26102,
			`{"clients":[{"id":"../../etc/passwd","password":"pw","email":"a2","enable":false}]}`,
			`{"clients":[{"id":"etcpasswd","password":"pw","email":"a2","enable":false}]}`,
			"path separator",
		},
		{
			// chap-secrets is whitespace-delimited.
			"space in vpn username", model.PPTP, 26103,
			`{"clients":[{"id":"bob smith","password":"pw","email":"a3","enable":false}]}`,
			`{"clients":[{"id":"bobsmith","password":"pw","email":"a3","enable":false}]}`,
			"spaces or tabs",
		},
		{
			// Xray's counter is named user>>><email>>>>traffic.
			"angle bracket in email", model.VLESS, 26104,
			`{"clients":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"a>>>b","enable":false}]}`,
			`{"clients":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"ab","enable":false}]}`,
			"control character or '>'",
		},
		{
			// subId is used directly as the /sub/<subId> path component.
			"path metachar in subId", model.VLESS, 26105,
			`{"clients":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"a5","subId":"../admin","enable":false}]}`,
			`{"clients":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"a5","subId":"admin","enable":false}]}`,
			"cannot contain",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// CONTROL FIRST, IN ITS OWN DATABASE.
			//
			// AddInbound runs several gates before the identity rules (a
			// certificate check, a port check, the shared-daemon check), and any of
			// them firing would reject the inbound for an unrelated reason while
			// this test still saw "rejected" and passed for the wrong cause. That
			// is not hypothetical: the openvpn case was masked by the cert gate,
			// and putting the control in the SAME database masked the l2tp case
			// behind the shared-IPsec-PSK check, because the control inbound had
			// already claimed the PSK.
			//
			// So the control creates the SAME inbound with a sanitized identity in
			// a fresh database. If that succeeds, nothing structural is in the way,
			// and the ONLY thing separating it from the case below is the offending
			// value.
			control := &model.Inbound{
				UserId: 1, Remark: "control", Port: tc.port, Protocol: tc.protocol,
				Enable: true, Settings: tc.control, Tag: "tag-" + tc.name,
			}
			if _, _, err := newInboundDB(t).AddInbound(control); err != nil {
				t.Fatalf("the control inbound was refused, so this case proves nothing "+
					"about the identity rules: %v", err)
			}

			in := &model.Inbound{
				UserId: 1, Remark: "t", Port: tc.port, Protocol: tc.protocol,
				Enable: true, Settings: tc.settings, Tag: "tag-" + tc.name,
			}
			_, _, err := newInboundDB(t).AddInbound(in)
			if err == nil {
				t.Fatal("accepted: the value reaches a credential file, a filename or a traffic counter")
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error should explain the cause (%q); got: %v", tc.wantIn, err)
			}
		})
	}
}

// The same values must be refused on the per-client route, which is the one an
// external script actually uses and which is reachable independently.
func TestAddInboundClientRejectsUnusableIdentities(t *testing.T) {
	svc := newInboundDB(t)
	host := seedInboundWithClients(t, model.L2TP, 26201, []map[string]any{
		{"id": "good", "password": "pw", "email": "existing", "enable": false, "slot": float64(0)},
	})

	_, err := svc.AddInboundClient(&model.Inbound{
		Id:       host.Id,
		Settings: `{"clients":[{"id":"evil\nroot ANY pw *","password":"pw","email":"newguy","enable":false}]}`,
	})
	if err == nil {
		t.Fatal("AddInboundClient accepted a username carrying a newline into chap-secrets")
	}
	if !strings.Contains(err.Error(), "control character") {
		t.Errorf("error should name the cause; got: %v", err)
	}
}

// Ordinary values must still go through: over-tightening here would refuse real
// accounts on upgrade, which is worse than the hole.
func TestOrdinaryIdentitiesStillAccepted(t *testing.T) {
	svc := newInboundDB(t)
	in := &model.Inbound{
		UserId: 1, Remark: "t", Port: 26301, Protocol: model.L2TP, Enable: true,
		Tag: "tag-ok",
		Settings: `{"clients":[
			{"id":"bob.smith-01","password":"p@ssw0rd!","email":"bob+tag@example.com","subId":"aBc123","enable":false,"slot":0},
			{"id":"user_2","password":"x","email":"UPPER@Example.COM","enable":false,"slot":1}
		]}`,
	}
	if _, _, err := svc.AddInbound(in); err != nil {
		t.Fatalf("a perfectly ordinary client list was refused: %v", err)
	}
}

// Shadowsocks multi-user carries a per-client cipher. AddInbound re-marshals
// every posted client through model.Client, so a field missing there is dropped
// with nothing reported: the account silently fell back to the inbound's cipher
// and only when created through THIS path, not /addClient.
func TestAddInboundKeepsPerClientShadowsocksMethod(t *testing.T) {
	svc := newInboundDB(t)
	in := &model.Inbound{
		UserId: 1, Remark: "t", Port: 26401, Protocol: model.Shadowsocks, Enable: true,
		Tag: "tag-ss",
		Settings: `{"method":"aes-256-gcm","clients":[
			{"password":"pw1","email":"ss1","method":"chacha20-ietf-poly1305","enable":false}
		]}`,
	}
	created, _, err := svc.AddInbound(in)
	if err != nil {
		t.Fatalf("AddInbound: %v", err)
	}
	clients := readClients(t, created.Id)
	if len(clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(clients))
	}
	if got, _ := clients[0]["method"].(string); got != "chacha20-ietf-poly1305" {
		t.Errorf("per-client method = %q, want %q: it was dropped, so the account "+
			"falls back to the inbound cipher and cannot connect with what it was given",
			got, "chacha20-ietf-poly1305")
	}
}

// The rules must be enforced on WRITES, not retroactively. A whole-inbound save
// posts EVERY client, so validating all of them would let one account created
// before these rules existed block every later edit to that inbound: its DNS, its
// remark, an unrelated new account. On a panel with hundreds of sold accounts
// that is an upgrade that bricks an inbound, which is worse than the hole.
func TestLegacyBadIdentityDoesNotBlockUnrelatedEdits(t *testing.T) {
	svc := newInboundDB(t)
	// Seeded directly, the way a row written before the rules existed looks: the
	// VPN username carries a space, which the service layer would now refuse.
	host := seedInboundWithClients(t, model.L2TP, 26501, []map[string]any{
		{"id": "legacy user", "password": "pw", "email": "legacy", "enable": false, "slot": float64(0)},
	})

	// An ordinary edit that does not touch that account at all.
	stored, err := svc.GetInbound(host.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	stored.Remark = "renamed"
	if _, _, err := svc.UpdateInbound(stored); err != nil {
		t.Fatalf("a legacy account blocked an unrelated edit to its inbound: %v", err)
	}

	// And adding a well-formed account alongside it must work too.
	stored, _ = svc.GetInbound(host.Id)
	stored.Settings = `{"clients":[
		{"id":"legacy user","password":"pw","email":"legacy","enable":false,"slot":0},
		{"id":"newguy","password":"pw2","email":"newguy","enable":false,"slot":1}
	]}`
	if _, _, err := svc.UpdateInbound(stored); err != nil {
		t.Fatalf("could not add a valid account beside a legacy one: %v", err)
	}
}

// The exemption is on the exact tuple, so a bad value can be KEPT but never
// edited into a different bad value.
func TestLegacyBadIdentityCannotBeEditedIntoAnotherBadValue(t *testing.T) {
	svc := newInboundDB(t)
	host := seedInboundWithClients(t, model.L2TP, 26601, []map[string]any{
		{"id": "legacy user", "password": "pw", "email": "legacy", "enable": false, "slot": float64(0)},
	})

	stored, err := svc.GetInbound(host.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	stored.Settings = `{"clients":[{"id":"still bad","password":"pw","email":"legacy","enable":false,"slot":0}]}`
	if _, _, err := svc.UpdateInbound(stored); err == nil {
		t.Fatal("a legacy bad username was edited into a different bad username")
	}
}
