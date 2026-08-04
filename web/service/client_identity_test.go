package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// A client's IDENTITY is the value the browser puts in the URL of
// /panel/api/inbounds/updateClient/:clientId and /:id/delClient/:clientId. It is not
// stored anywhere: both ends recompute it from the protocol, which is why the two
// ends can silently disagree.
//
// They did. The switch was copy-pasted into five Go functions and two templates, and
// openconnect/sstp/ikev2 were only ever added to some of them: the browser keyed an
// edit on the client's password while the backend looked the account up by id, so
// every edit of an IKEv2/SSTP/OpenConnect client failed with "empty client ID" and
// every delete removed nobody while reporting success.
//
// These tests pin the contract on both sides of the wire.

func TestClientIdentityKeyPerProtocol(t *testing.T) {
	cases := map[model.Protocol]string{
		// Username+password VPN protocols, keyed on the password.
		model.Trojan:      "password",
		model.L2TP:        "password",
		model.PPTP:        "password",
		model.OPENVPN:     "password",
		model.OPENCONNECT: "password",
		model.SSTP:        "password",
		model.IKEV2:       "password",

		// Password-credential native Xray protocols: anytls authenticates on the
		// password alone; naive carries a Basic username too, but it is optional and
		// renameable, so the password stays the addressable field.
		model.ANYTLS: "password",
		model.NAIVE:  "password",

		model.Shadowsocks: "email",
		model.Hysteria:    "auth",
		model.Hysteria2:   "auth",

		// UUID-identity and email-identity protocols both key on "id"; the latter
		// store id=email in their settings JSON. tuic carries a uuid AND a password
		// and is keyed on the uuid.
		model.VMESS:   "id",
		model.VLESS:   "id",
		model.WGC:     "id",
		model.AWG:     "id",
		model.MTPROTO: "id",
		model.SSH:     "id",
		model.TUIC:    "id",
	}
	for protocol, want := range cases {
		if got := clientIdentityKey(protocol); got != want {
			t.Errorf("clientIdentityKey(%q) = %q, want %q", protocol, got, want)
		}
	}
}

func TestClientIdentityReadsTheKeyedField(t *testing.T) {
	client := model.Client{ID: "the-id", Password: "the-password", Email: "the-email", Auth: "the-auth"}
	cases := map[model.Protocol]string{
		model.IKEV2:       "the-password",
		model.SSTP:        "the-password",
		model.OPENCONNECT: "the-password",
		model.Shadowsocks: "the-email",
		model.Hysteria2:   "the-auth",
		model.VLESS:       "the-id",
		model.WGC:         "the-id",
	}
	for protocol, want := range cases {
		if got := clientIdentity(protocol, client); got != want {
			t.Errorf("clientIdentity(%q) = %q, want %q", protocol, got, want)
		}
	}
}

// The browser computes the SAME identity independently, in
// web/assets/js/model/inbound.js. A disagreement between the two is invisible until
// an operator tries to edit a client, so it is checked here rather than left to a
// bug report. This parses the shipped JS instead of restating it: a copy would drift
// exactly like the ones it replaced.
func TestClientIdentityMatchesTheBrowser(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "assets", "js", "model", "inbound.js"))
	if err != nil {
		t.Fatalf("read inbound.js: %v", err)
	}
	js := string(src)

	protocols := parseJsProtocols(t, js)
	browser := parseJsClientIdentity(t, js, protocols)

	// Every protocol the JS names must resolve the same way in Go...
	for protocol, field := range browser {
		if got := clientIdentityKey(model.Protocol(protocol)); got != field {
			t.Errorf("protocol %q: browser keys on %q, clientIdentityKey says %q", protocol, field, got)
		}
	}
	// ...and, the other way round, no protocol Go treats specially may be missing
	// from the JS switch, which would silently fall through to its `default: id`.
	for _, protocol := range []model.Protocol{
		model.Trojan, model.L2TP, model.PPTP, model.OPENVPN,
		model.OPENCONNECT, model.SSTP, model.IKEV2,
		model.Shadowsocks, model.Hysteria,
	} {
		if _, ok := browser[string(protocol)]; !ok {
			t.Errorf("protocol %q keys on %q in Go but is absent from getClientIdentity() in inbound.js",
				protocol, clientIdentityKey(protocol))
		}
	}
}

// parseJsProtocols reads `const Protocols = { VMESS: 'vmess', ... }` into
// name -> value ("VMESS" -> "vmess").
func parseJsProtocols(t *testing.T, js string) map[string]string {
	t.Helper()
	block := jsBlockAfter(t, js, "const Protocols = {")
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(\w+)\s*:\s*'([^']+)'`).FindAllStringSubmatch(block, -1) {
		out[m[1]] = m[2]
	}
	if len(out) == 0 {
		t.Fatal("parsed no entries out of the Protocols map")
	}
	return out
}

// parseJsClientIdentity reads the getClientIdentity() switch into
// protocol value -> client field ("ikev2" -> "password"). Fallthrough case labels
// accumulate until the return that closes them.
func parseJsClientIdentity(t *testing.T, js string, protocols map[string]string) map[string]string {
	t.Helper()
	body := jsBlockAfter(t, js, "function getClientIdentity(protocol, client) {")
	caseRe := regexp.MustCompile(`^case Protocols\.(\w+):`)
	returnRe := regexp.MustCompile(`^return client\.(\w+);`)

	out := map[string]string{}
	var pending []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if m := caseRe.FindStringSubmatch(line); m != nil {
			value, ok := protocols[m[1]]
			if !ok {
				t.Fatalf("getClientIdentity names Protocols.%s, which the Protocols map does not define", m[1])
			}
			pending = append(pending, value)
			continue
		}
		if m := returnRe.FindStringSubmatch(line); m != nil {
			for _, protocol := range pending {
				out[protocol] = m[1]
			}
			pending = nil
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no cases out of getClientIdentity()")
	}
	return out
}

// jsBlockAfter returns the brace-balanced text following marker (which must end in
// the opening brace), so the regexes above cannot wander into neighbouring code.
func jsBlockAfter(t *testing.T, js, marker string) string {
	t.Helper()
	start := strings.Index(js, marker)
	if start < 0 {
		t.Fatalf("inbound.js no longer contains %q", marker)
	}
	rest := js[start+len(marker)-1:] // keep the opening brace
	depth := 0
	for i, r := range rest {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[1:i]
			}
		}
	}
	t.Fatalf("unbalanced braces after %q", marker)
	return ""
}

// identityClient builds a client carrying BOTH an id and a password, the shape the
// UI produces for every username+password protocol. The point of the test is that
// the two are different strings, so keying on the wrong one cannot accidentally pass.
func identityClient(username, password, email string) map[string]any {
	return map[string]any{
		"id":       username,
		"password": password,
		"email":    email,
		"enable":   false,
	}
}

// seedClientStats gives each account the client_traffics row AddClientStat would
// have created. The delete path reads it before removing anything, so without one a
// real deletion fails on "record not found" for reasons unrelated to identity.
func seedClientStats(t *testing.T, inboundId int, emails ...string) {
	t.Helper()
	for _, email := range emails {
		row := &xray.ClientTraffic{InboundId: inboundId, Email: email, Enable: true}
		if err := database.GetDB().Create(row).Error; err != nil {
			t.Fatalf("seed client_traffics for %q: %v", email, err)
		}
	}
}

// The regression: an edit addressed by the identity the BROWSER computes must find
// the account. Before the fix this passed for l2tp/pptp/openvpn/trojan and failed
// for openconnect/sstp/ikev2 with "empty client ID".
func TestUpdateInboundClientFindsClientByBrowserIdentity(t *testing.T) {
	for _, protocol := range []model.Protocol{
		model.IKEV2, model.SSTP, model.OPENCONNECT,
		model.L2TP, model.PPTP, model.OPENVPN, model.Trojan,
		model.VLESS,
	} {
		t.Run(string(protocol), func(t *testing.T) {
			s := newInboundDB(t)
			email := "user@" + string(protocol)
			client := identityClient("username-1", "password-1", email)
			inbound := &model.Inbound{
				UserId:   1,
				Tag:      "inbound-" + string(protocol),
				Port:     11000,
				Protocol: protocol,
				Enable:   false,
				Settings: clientSettings(client),
			}
			if err := database.GetDB().Create(inbound).Error; err != nil {
				t.Fatalf("seed inbound: %v", err)
			}

			// What the modal would put in the URL.
			clientId := clientIdentity(protocol, model.Client{
				ID: "username-1", Password: "password-1", Email: email,
			})
			if clientId == "" {
				t.Fatalf("no identity for protocol %q", protocol)
			}

			// Rename the account's comment only: the identity field is untouched, so
			// the lookup must still match on the value the modal opened with.
			updated := identityClient("username-1", "password-1", email)
			updated["comment"] = "edited"
			payload := &model.Inbound{Id: inbound.Id, Settings: clientSettings(updated)}

			if _, err := s.UpdateInboundClient(payload, clientId); err != nil {
				t.Fatalf("UpdateInboundClient by %s identity %q: %v",
					clientIdentityKey(protocol), clientId, err)
			}

			stored, err := s.GetInbound(inbound.Id)
			if err != nil {
				t.Fatalf("GetInbound: %v", err)
			}
			var got struct {
				Clients []struct {
					Comment string `json:"comment"`
				} `json:"clients"`
			}
			if err := json.Unmarshal([]byte(stored.Settings), &got); err != nil {
				t.Fatalf("parse settings: %v", err)
			}
			if len(got.Clients) != 1 || got.Clients[0].Comment != "edited" {
				t.Errorf("edit did not land: %s", stored.Settings)
			}
		})
	}
}

// The delete twin. It used to keep every client and still report success, so the row
// vanished from the table until the next refresh put it back.
func TestDelInboundClientRejectsAnIdentityItCannotFind(t *testing.T) {
	s := newInboundDB(t)
	inbound := &model.Inbound{
		UserId:   1,
		Tag:      "inbound-del",
		Port:     11001,
		Protocol: model.IKEV2,
		Enable:   false,
		Settings: clientSettings(
			identityClient("username-1", "password-1", "a@ikev2"),
			identityClient("username-2", "password-2", "b@ikev2"),
		),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	seedClientStats(t, inbound.Id, "a@ikev2", "b@ikev2")

	// The username is NOT the identity for ikev2; addressing by it must fail loudly
	// rather than delete nobody and claim success.
	if _, err := s.DelInboundClient(inbound.Id, "username-1"); err == nil {
		t.Error("deleting by a non-identity value reported success")
	}
	if emails := emailsInSettings(t, s, inbound.Id); len(emails) != 2 {
		t.Errorf("failed delete still mutated the inbound: %v", emails)
	}

	// The identity the browser sends does delete.
	if _, err := s.DelInboundClient(inbound.Id, "password-1"); err != nil {
		t.Fatalf("DelInboundClient by password: %v", err)
	}
	emails := emailsInSettings(t, s, inbound.Id)
	if len(emails) != 1 || emails[0] != "b@ikev2" {
		t.Errorf("wrong client removed: %v", emails)
	}
}

// A client stored without the identity field must not take the request down with it.
// The delete path asserted the field to string unconditionally, so one legacy record
// panicked the handler.
func TestDelInboundClientSurvivesAClientMissingTheIdentityField(t *testing.T) {
	s := newInboundDB(t)
	inbound := &model.Inbound{
		UserId:   1,
		Tag:      "inbound-legacy",
		Port:     11002,
		Protocol: model.IKEV2,
		Enable:   false,
		Settings: clientSettings(
			map[string]any{"id": "username-legacy", "email": "legacy@ikev2", "enable": false},
			identityClient("username-2", "password-2", "b@ikev2"),
		),
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	seedClientStats(t, inbound.Id, "legacy@ikev2", "b@ikev2")
	if _, err := s.DelInboundClient(inbound.Id, "password-2"); err != nil {
		t.Fatalf("DelInboundClient alongside a passwordless client: %v", err)
	}
	if emails := emailsInSettings(t, s, inbound.Id); len(emails) != 1 || emails[0] != "legacy@ikev2" {
		t.Errorf("wrong client removed: %v", emails)
	}
}

// The by-email helpers (the enable toggle, the traffic/expiry/IP-limit resets) look
// the account up themselves and then hand the id to UpdateInboundClient. They carried
// their own copy of the identity switch, and it was the most out-of-date of the lot:
// it listed only trojan/l2tp/pptp, so OpenVPN was already broken here before IKEv2
// and friends were ever added. Both ends read clientIdentity() now, so this pins that
// they still agree.
func TestToggleClientEnableByEmailFindsPasswordKeyedClients(t *testing.T) {
	// VPN protocols only. Enabling a client pushes it to the live Xray, and
	// XrayAPI.AddUser bails out at its `default:` for anything that is not a native
	// Xray protocol; a vless client here would reach the nil gRPC handle instead.
	for _, protocol := range []model.Protocol{
		model.IKEV2, model.SSTP, model.OPENCONNECT, model.OPENVPN, model.L2TP,
	} {
		t.Run(string(protocol), func(t *testing.T) {
			s := newInboundDB(t)
			email := "toggle@" + string(protocol)
			inbound := &model.Inbound{
				UserId:   1,
				Tag:      "inbound-toggle-" + string(protocol),
				Port:     12000,
				Protocol: protocol,
				Enable:   false,
				Settings: clientSettings(identityClient("username-1", "password-1", email)),
			}
			if err := database.GetDB().Create(inbound).Error; err != nil {
				t.Fatalf("seed inbound: %v", err)
			}
			seedClientStats(t, inbound.Id, email)

			// Returns (newEnabledState, needRestart, error).
			if enabled, _, err := s.ToggleClientEnableByEmail(email); err != nil {
				t.Fatalf("ToggleClientEnableByEmail: %v", err)
			} else if !enabled {
				t.Error("toggle reported the client still disabled")
			}
			// And it has to have actually landed in the settings JSON, which is the
			// half that silently did nothing when the two identity switches disagreed.
			stored, err := s.GetInbound(inbound.Id)
			if err != nil {
				t.Fatalf("GetInbound: %v", err)
			}
			clients, err := s.GetClients(stored)
			if err != nil {
				t.Fatalf("GetClients: %v", err)
			}
			if len(clients) != 1 || !clients[0].Enable {
				t.Errorf("toggle did not persist: %s", stored.Settings)
			}
		})
	}
}

// Copying a client into another inbound wiped every credential and then minted only
// the one its target protocol's case named. The username+password protocols had no
// case, so a copy landed with a username and NO password: an account the table
// listed, RADIUS could never authenticate, and no id-keyed path could address.
func TestBuildTargetClientFromSourceMintsAUsableCredential(t *testing.T) {
	s := &InboundService{}
	source := model.Client{ID: "src-id", Password: "src-password", Email: "src@example.com"}

	for _, protocol := range []model.Protocol{
		model.VMESS, model.VLESS, model.Trojan, model.Shadowsocks, model.Hysteria,
		model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2,
		model.WGC, model.AWG, model.MTPROTO, model.SSH,
	} {
		t.Run(string(protocol), func(t *testing.T) {
			target, err := s.buildTargetClientFromSource(source, protocol, "copy@example.com", "")
			if err != nil {
				t.Fatalf("buildTargetClientFromSource: %v", err)
			}
			if got := clientIdentity(protocol, target); got == "" {
				t.Errorf("copied client has no %s, so nothing can address it", clientIdentityKey(protocol))
			}
			// No credential may survive the copy: two accounts sharing one is the
			// whole reason they are wiped first.
			if target.Password != "" && target.Password == source.Password {
				t.Error("copied client reuses the source password")
			}
			if target.ID != "" && target.ID == source.ID {
				t.Error("copied client reuses the source id")
			}
			// A username+password protocol needs BOTH halves to authenticate.
			switch protocol {
			case model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2:
				if target.ID == "" || target.Password == "" {
					t.Errorf("username+password protocol got id=%q password=%q", target.ID, target.Password)
				}
			case model.WGC, model.AWG, model.MTPROTO, model.SSH:
				if target.ID != "copy@example.com" {
					t.Errorf("email-identity protocol got id=%q, want the email", target.ID)
				}
			}
		})
	}
}
