package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// The psk/eap-tls admission gate is the whole of quota/disable enforcement for those two
// modes: charon authenticates them locally, so a loaded connection admits the account no
// matter what the DB says. If ikev2Admissible ever returns true for a disabled account,
// the account silently keeps browsing after its quota trips (the bug this replaced).
func TestIkev2Admissible(t *testing.T) {
	settings := func(mode string, enable bool) *ikev2Settings {
		return &ikev2Settings{
			AuthMode: mode,
			Clients:  []ikev2Client{{ID: "u1", Email: "u1@t", Enable: enable}},
		}
	}
	quotaHit := map[string]bool{"u1@t": true}
	none := map[string]bool{}

	tests := []struct {
		name     string
		settings *ikev2Settings
		disabled map[string]bool
		want     bool
	}{
		{"psk enabled", settings("psk", true), none, true},
		{"psk switched off", settings("psk", false), none, false},
		{"psk over quota", settings("psk", true), quotaHit, false},
		{"eap-tls enabled", settings("eap-tls", true), none, true},
		{"eap-tls switched off", settings("eap-tls", false), none, false},
		{"eap-tls over quota", settings("eap-tls", true), quotaHit, false},

		// eap-mschapv2 re-authenticates against the panel RADIUS on every connect, which
		// reads client_traffics live, so its conn must stay loaded even when disabled:
		// unloading it would break the OTHER accounts on a multi-account inbound.
		{"eap-mschapv2 switched off keeps conn", settings("eap-mschapv2", false), quotaHit, true},
		{"eap-mschapv2 default mode keeps conn", settings("", false), quotaHit, true},

		// No account owns the inbound: nothing to enforce, keep prior behavior.
		{"psk with no clients", &ikev2Settings{AuthMode: "psk"}, none, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ikev2Admissible(tc.settings, tc.disabled); got != tc.want {
				t.Fatalf("ikev2Admissible = %v, want %v", got, tc.want)
			}
		})
	}
}

// admissionSig gates the reload, so a signature that fails to move when an account is
// disabled would silently restore the bug (the config would never be regenerated), while
// one that moves on every tick would reload charon every 10s forever.
func TestIkev2AdmissionSigTracksAccountState(t *testing.T) {
	s := &Ikev2Service{}
	enabled := `{"authMode":"psk","psk":"secret","clients":[{"id":"u1","email":"u1@t","enable":true}]}`
	inbounds := []*model.Inbound{{Id: 7, Enable: true, Settings: enabled}}
	none := map[string]bool{}

	base := s.admissionSig(inbounds, none)
	if base != s.admissionSig(inbounds, none) {
		t.Fatal("signature is unstable across identical calls: charon would reload every tick")
	}
	if quota := s.admissionSig(inbounds, map[string]bool{"u1@t": true}); quota == base {
		t.Fatal("signature did not move when the account went over quota: no reload, conn stays loaded")
	}

	off := []*model.Inbound{{Id: 7, Enable: true,
		Settings: `{"authMode":"psk","psk":"secret","clients":[{"id":"u1","email":"u1@t","enable":false}]}`}}
	if s.admissionSig(off, none) == base {
		t.Fatal("signature did not move when the account was switched off")
	}

	// An eap-mschapv2 account going over quota must NOT move the signature: RADIUS
	// enforces it, so reloading charon would be pure churn.
	eap := []*model.Inbound{{Id: 7, Enable: true,
		Settings: `{"authMode":"eap-mschapv2","clients":[{"id":"u1","email":"u1@t","enable":true}]}`}}
	if s.admissionSig(eap, map[string]bool{"u1@t": true}) != s.admissionSig(eap, none) {
		t.Fatal("eap-mschapv2 quota moved the signature: charon would reload for nothing")
	}
}
