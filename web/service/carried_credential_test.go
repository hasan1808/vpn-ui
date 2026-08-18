package service

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// Credentials CARRIED on an entry addressed to another protocol.
//
// The Clients page edits an account and posts every credential column of it to
// whichever inbound the write happens to be addressed to, so a VPN login name
// legitimately arrives on a vless entry under its own key. validateClientIdentities
// keyed its VPN-username rules on the ADDRESSED inbound's protocol and on client.ID,
// so that value was judged as a vless uuid, which is to say not at all.
//
// It then reached account.VpnUsername through the accounts sync and was projected
// onto the account's openvpn membership as its "id", which openvpn.go turns into a
// CCD filename written as root.
func TestCarriedVpnUsernameIsValidated(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "carried@example.com"

	vless := seedInboundWithClients(t, model.VLESS, 26901, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true},
	})
	openvpn := seedInboundWithClients(t, model.OPENVPN, 26902, []map[string]any{})
	svc.MigrationAccounts()
	account, err := svc.GetAccountByEmail(email)
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	account.UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	account.VpnUsername = "safe-login"
	account.Password = "pw"
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := svc.ApplyMemberships(email, []int{vless.Id, openvpn.Id}, nil, true); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	inbounds := &InboundService{}
	// Exactly what the Clients form posts: the write is addressed to the vless
	// inbound (the lowest-id membership), and the VPN login rides along under its
	// own key.
	posted := `{"clients":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"` + email +
		`","enable":true,"vpnUsername":"../../../../etc/cron.d/pwn","password":"pw"}]}`
	_, err = inbounds.UpdateInboundClient(&model.Inbound{
		Id: vless.Id, Settings: posted,
	}, "3fa85f64-5717-4562-b3fc-2c963f66afa6")
	if err == nil {
		// What the controller does next on every client write: mirror the inbound's
		// settings into the accounts layer, which is where the carried key is lifted.
		if _, merr := svc.ApplyMemberships(email, []int{vless.Id, openvpn.Id}, nil, true); merr != nil {
			t.Fatalf("ApplyMemberships: %v", merr)
		}
		reread, _ := svc.GetAccountByEmail(email)
		t.Fatalf("the write was accepted and account.VpnUsername is now %q. It becomes an "+
			"openvpn CCD filename (web/service/openvpn.go writeFile), so a path separator here "+
			"writes outside the block directory as root.", reread.VpnUsername)
	}
	if !strings.Contains(err.Error(), "path separator") {
		t.Errorf("refused with %q; want the path-separator rule", err)
	}
}

// The control. The same shape with a legal login name has to be ACCEPTED and has to
// reach the account, or the check above proves only that the write path is broken.
func TestCarriedVpnUsernameStillReachesTheAccount(t *testing.T) {
	svc := newAccountsDB(t)
	const email = "carriedok@example.com"

	vless := seedInboundWithClients(t, model.VLESS, 26911, []map[string]any{
		{"id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "email": email, "enable": true},
	})
	openvpn := seedInboundWithClients(t, model.OPENVPN, 26912, []map[string]any{})
	svc.MigrationAccounts()
	account, err := svc.GetAccountByEmail(email)
	if err != nil || account == nil {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	account.UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
	account.VpnUsername = "old-login"
	account.Password = "pw"
	if err := database.GetDB().Save(account).Error; err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := svc.ApplyMemberships(email, []int{vless.Id, openvpn.Id}, nil, true); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}

	inbounds := &InboundService{}
	posted := `{"clients":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"` + email +
		`","enable":true,"vpnUsername":"new-login","password":"pw"}]}`
	if _, err := inbounds.UpdateInboundClient(&model.Inbound{Id: vless.Id, Settings: posted},
		"3fa85f64-5717-4562-b3fc-2c963f66afa6"); err != nil {
		t.Fatalf("a legal carried login name was refused: %v", err)
	}
	if _, err := svc.ApplyMemberships(email, []int{vless.Id, openvpn.Id}, nil, true); err != nil {
		t.Fatalf("ApplyMemberships: %v", err)
	}
	reread, _ := svc.GetAccountByEmail(email)
	if reread.VpnUsername != "new-login" {
		t.Errorf("account.VpnUsername = %q; want new-login. The carried key is how the Clients "+
			"form edits a VPN login from a page that is not addressing a VPN inbound.",
			reread.VpnUsername)
	}
	_ = openvpn
}

// A 2022-blake3 cipher does not take an arbitrary string: the user PSK must be
// base64 of exactly the cipher's key length. Nothing refused a bad one at any layer,
// so the account was created, listed, looked healthy and could never connect.
func TestShadowsocks2022RefusesAnUnusableKey(t *testing.T) {
	newAccountsDB(t)
	inbound := &model.Inbound{
		Protocol: model.Shadowsocks,
		Settings: `{"method":"2022-blake3-aes-256-gcm","clients":[]}`,
	}

	bad := []model.Client{{Email: "ss@example.com", Password: "hunter2"}}
	if err := ValidateShadowsocksKeys(inbound, bad, nil); err == nil {
		t.Error("a plain string was accepted as a 2022-blake3-aes-256-gcm key")
	}

	// 24 bytes where the cipher wants 32: the exact shape a dashless uuid decodes to,
	// which is what an account arriving from another protocol carries.
	short := make([]byte, 24)
	if err := ValidateShadowsocksKeys(inbound,
		[]model.Client{{Email: "ss@example.com", Password: base64.StdEncoding.EncodeToString(short)}},
		nil); err == nil {
		t.Error("a 24-byte key was accepted by a 32-byte cipher")
	}

	good := make([]byte, 32)
	if err := ValidateShadowsocksKeys(inbound,
		[]model.Client{{Email: "ss@example.com", Password: base64.StdEncoding.EncodeToString(good)}},
		nil); err != nil {
		t.Errorf("a correct 32-byte key was refused: %v", err)
	}

	// Blank is the ordinary path for an account joining from another protocol: the
	// projection mints a correct PSK for a membership that has none.
	if err := ValidateShadowsocksKeys(inbound,
		[]model.Client{{Email: "ss@example.com", Password: ""}}, nil); err != nil {
		t.Errorf("a blank password was refused: %v", err)
	}

	// Every other cipher takes any string, and must keep doing so.
	legacy := &model.Inbound{Protocol: model.Shadowsocks, Settings: `{"method":"aes-256-gcm"}`}
	if err := ValidateShadowsocksKeys(legacy, bad, nil); err != nil {
		t.Errorf("a non-2022 cipher refused a plain password: %v", err)
	}
}

// An account created before the check must stay editable, or an upgrade makes the
// inbound unsaveable until every historical row is fixed by hand.
func TestShadowsocks2022ExemptsAnUnchangedKey(t *testing.T) {
	newAccountsDB(t)
	inbound := &model.Inbound{
		Protocol: model.Shadowsocks,
		Settings: `{"method":"2022-blake3-aes-256-gcm","clients":[]}`,
	}
	stored := []model.Client{{Email: "old@example.com", Password: "hunter2"}}

	// Same bad password, some other field edited: allowed through.
	same := []model.Client{{Email: "old@example.com", Password: "hunter2", TotalGB: 5}}
	if err := ValidateShadowsocksKeys(inbound, same, stored); err != nil {
		t.Errorf("editing the quota of a pre-existing bad row was refused: %v", err)
	}

	// Editing the password itself holds it to the current rule.
	changed := []model.Client{{Email: "old@example.com", Password: "hunter3"}}
	if err := ValidateShadowsocksKeys(inbound, changed, stored); err == nil {
		t.Error("a bad password was allowed to be edited into a different bad password")
	}
}
