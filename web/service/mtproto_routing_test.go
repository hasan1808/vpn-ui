package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// mtprotoRoutingFixture is an inbound with two accounts and no ad tag, so it
// egresses through Xray.
func mtprotoRoutingFixture(t *testing.T) (*model.Inbound, *mtprotoSettings) {
	t.Helper()
	settings := &mtprotoSettings{Clients: []mtprotoClient{
		{Email: "alice@t", Secret: "00112233445566778899aabbccddeeff", Enable: true, ModeClassic: true, ModeTls: true, TlsDomain: "www.cloudflare.com"},
		{Email: "bob@t", Secret: "ffeeddccbbaa99887766554433221100", Enable: true, ModeSecure: true},
		// Disabled, but still a telemt account ([access.user_enabled] = false).
		{Email: "carol@t", Secret: "aabbccddeeff00112233445566778899", Enable: false, ModeClassic: true},
		// No mode enabled: nothing can dial it, so it is not an account at all.
		{Email: "dave@t", Secret: "99887766554433221100ffeeddccbbaa", Enable: true},
	}}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return &model.Inbound{Id: 7, Port: 8443, Tag: "inbound-8443", Protocol: model.MTPROTO, Settings: string(raw)}, settings
}

func socksAccountsOf(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	var parsed struct {
		Auth     string `json:"auth"`
		Accounts []struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Auth != "password" {
		t.Fatalf("socks auth = %q, want %q: without password auth the account never reaches Xray and per-client rules cannot match", parsed.Auth, "password")
	}
	out := make(map[string]string, len(parsed.Accounts))
	for _, a := range parsed.Accounts {
		out[a.User] = a.Pass
	}
	return out
}

// TestMtprotoSocksCarriesPerClientIdentity pins the per-client routing contract:
// each enabled account must have a socks account, since that username is the only
// channel by which a relay (no per-client IP) can tell Xray who the client is.
func TestMtprotoSocksCarriesPerClientIdentity(t *testing.T) {
	inbound, _ := mtprotoRoutingFixture(t)
	s := &MtprotoService{}

	cfg := s.GetSocksConfig(inbound)
	if cfg == nil {
		t.Fatal("GetSocksConfig returned nil for a routed (no-adtag) inbound")
	}
	if cfg.Tag != inbound.Tag {
		t.Errorf("socks tag = %q, want %q (inbound-level rules match on this)", cfg.Tag, inbound.Tag)
	}

	accounts := socksAccountsOf(t, cfg.Settings)
	// The socks account list mirrors [access.users] exactly, disabled accounts
	// included: telemt is the enforcement point (it rejects a disabled account at the
	// MTProto handshake, long before any upstream connection), and this listener is
	// loopback-only with pass == user, so it asserts identity rather than guarding
	// access. Mirroring keeps one list authoritative instead of two that can diverge.
	for _, email := range []string{"alice@t", "bob@t", "carol@t"} {
		if _, ok := accounts[email]; !ok {
			t.Errorf("no socks account for client %q: Xray would reject its traffic", email)
		}
	}
	// An account with no mode enabled is unreachable, so it is not rendered at all.
	if _, ok := accounts["dave@t"]; ok {
		t.Error("dave@t has no mode enabled but got a socks account")
	}
	// telemt's own DC-reachability probes carry no account and fall back to this
	// identity. Drop it and every probe fails the handshake, and telemt reports all
	// Telegram DCs unreachable.
	if _, ok := accounts[mtprotoSystemAccount]; !ok {
		t.Errorf("no socks account for %q: telemt's DC probes would fail to authenticate", mtprotoSystemAccount)
	}
}

// TestMtprotoUpstreamRequestsAccountIdentity guards the telemt side of the same
// contract, plus the reason accounts must NOT be listed in [[upstreams]].
func TestMtprotoUpstreamRequestsAccountIdentity(t *testing.T) {
	inbound, settings := mtprotoRoutingFixture(t)
	s := &MtprotoService{}
	cfg := s.buildServerConfig(inbound, settings)

	if !strings.Contains(cfg, "socks_user_from_account = true") {
		t.Error("upstream lacks socks_user_from_account: telemt would present no identity and every client would share one route")
	}
	if !strings.Contains(cfg, `username = "`+mtprotoSystemAccount+`"`) {
		t.Error("upstream lacks the fallback identity for account-less connections")
	}

	// [[upstreams]] is restart-only, so anything per-account here would drop every
	// live connection on each client add. Identity travels per-connection instead.
	upstream := cfg[strings.Index(cfg, "[[upstreams]]"):]
	if end := strings.Index(upstream, "[access."); end > 0 {
		upstream = upstream[:end]
	}
	for _, email := range []string{"alice@t", "bob@t"} {
		if strings.Contains(upstream, email) {
			t.Errorf("account %q appears in [[upstreams]], which is restart-only: adding a client would drop live connections", email)
		}
	}
}

// TestMtprotoAdtagDisablesRouting pins the mutual exclusion: middle-proxy mode
// needs an unaltered egress 4-tuple, so there is no socks hop to carry identity.
func TestMtprotoAdtagDisablesRouting(t *testing.T) {
	inbound, settings := mtprotoRoutingFixture(t)
	settings.Clients[0].AdtagEnable = true
	settings.Clients[0].Adtag = "0123456789abcdef0123456789abcdef"
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	inbound.Settings = string(raw)

	s := &MtprotoService{}
	if cfg := s.GetSocksConfig(inbound); cfg != nil {
		t.Error("adtag inbound still got a socks inbound: its traffic cannot survive a proxy hop")
	}
	if cfg := s.buildServerConfig(inbound, settings); !strings.Contains(cfg, `type = "direct"`) {
		t.Error("adtag inbound is not on a direct upstream")
	}
}
