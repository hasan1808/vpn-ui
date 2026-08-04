package service

import (
	"encoding/json"
	"strings"
	"testing"
)

// Masking and keep-on-blank are one mechanism, not two, and the pair is what makes an
// outbound editable without its secrets ever reaching the browser. Tested together
// because each is harmless-looking alone and wrong in a different direction: mask
// without merge and no tunnel can be edited, merge without mask and every private key
// is served to the panel.

// fakeVpnOutDriver is a driver in name only. The framework never inspects settings, so
// a stub is enough to exercise everything around it.
type fakeVpnOutDriver struct {
	secrets []string
}

func (f *fakeVpnOutDriver) Up(VpnOutboundConfig) (string, error)    { return "fake0", nil }
func (f *fakeVpnOutDriver) Down(VpnOutboundConfig) error            { return nil }
func (f *fakeVpnOutDriver) Status(VpnOutboundConfig) (bool, string) { return true, "" }
func (f *fakeVpnOutDriver) Validate(VpnOutboundConfig) error        { return nil }
func (f *fakeVpnOutDriver) SecretKeys() []string                    { return f.secrets }

func init() {
	// Registered from init so it is present however the tests are ordered, and under
	// names no real protocol uses.
	RegisterVpnOutDriver("testsecret", &fakeVpnOutDriver{secrets: []string{"privateKey", "password"}})
	RegisterVpnOutDriver("testplain", &fakeVpnOutDriver{})
}

func TestMaskVpnOutSecretsRemovesDeclaredKeys(t *testing.T) {
	in := json.RawMessage(`{"endpoint":"1.2.3.4:51820","privateKey":"SECRET","password":"hunter2","mtu":1420}`)
	got := maskVpnOutSecrets("testsecret", in)

	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("masked output is not JSON: %v", err)
	}
	for _, gone := range []string{"privateKey", "password"} {
		if _, present := obj[gone]; present {
			t.Errorf("%q survived masking", gone)
		}
	}
	// Removed, NOT blanked. A blanked key is present-and-empty, and the merge below
	// treats present as authoritative, so the first save would wipe the stored secret.
	if strings.Contains(string(got), `"privateKey"`) {
		t.Error("privateKey was blanked rather than removed")
	}
	for _, kept := range []string{"endpoint", "mtu"} {
		if _, present := obj[kept]; !present {
			t.Errorf("%q was masked but is not a secret", kept)
		}
	}
}

// A driver that declares nothing must not have its settings touched, and one whose
// blob will not parse must not be shipped verbatim on the theory that it is probably
// fine.
func TestMaskVpnOutSecretsEdgeCases(t *testing.T) {
	plain := json.RawMessage(`{"a":1,"privateKey":"not-declared-secret"}`)
	if got := string(maskVpnOutSecrets("testplain", plain)); got != string(plain) {
		t.Errorf("a driver declaring no secrets had its settings rewritten: %s", got)
	}
	if got := maskVpnOutSecrets("testsecret", json.RawMessage(`not json at all`)); got != nil {
		t.Errorf("an unparseable blob was passed through as %s, want it dropped", got)
	}
	if got := maskVpnOutSecrets("nosuchkind", json.RawMessage(`{"privateKey":"x"}`)); got != nil {
		t.Errorf("settings for an unknown kind were passed through as %s, want them dropped", got)
	}
}

func TestMergeKeptSettings(t *testing.T) {
	stored := json.RawMessage(`{"endpoint":"1.2.3.4:51820","privateKey":"SECRET","mtu":1420}`)

	t.Run("an absent key keeps the stored value", func(t *testing.T) {
		// Exactly what the panel posts after a masked list: no privateKey at all.
		incoming := json.RawMessage(`{"endpoint":"5.6.7.8:51820","mtu":1380}`)
		var got map[string]any
		if err := json.Unmarshal(mergeKeptSettings(incoming, stored), &got); err != nil {
			t.Fatal(err)
		}
		if got["privateKey"] != "SECRET" {
			t.Errorf("privateKey = %v, want the stored SECRET to survive the edit", got["privateKey"])
		}
		if got["endpoint"] != "5.6.7.8:51820" {
			t.Errorf("endpoint = %v, want the edit to win", got["endpoint"])
		}
	})

	t.Run("an explicitly empty value wins, so a secret can be cleared", func(t *testing.T) {
		incoming := json.RawMessage(`{"privateKey":""}`)
		var got map[string]any
		if err := json.Unmarshal(mergeKeptSettings(incoming, stored), &got); err != nil {
			t.Fatal(err)
		}
		if got["privateKey"] != "" {
			t.Errorf("privateKey = %v, want the explicit empty to clear it", got["privateKey"])
		}
	})

	t.Run("nothing stored means the incoming stands", func(t *testing.T) {
		incoming := json.RawMessage(`{"a":1}`)
		if got := string(mergeKeptSettings(incoming, nil)); got != string(incoming) {
			t.Errorf("got %s, want %s", got, incoming)
		}
	})

	t.Run("nothing incoming keeps the whole stored blob", func(t *testing.T) {
		if got := string(mergeKeptSettings(nil, stored)); got != string(stored) {
			t.Errorf("got %s, want the stored blob", got)
		}
	})

	t.Run("a non-object on either side is not merged", func(t *testing.T) {
		incoming := json.RawMessage(`"a bare string"`)
		if got := string(mergeKeptSettings(incoming, stored)); got != string(incoming) {
			t.Errorf("got %s, want the incoming value to stand", got)
		}
	})
}

// The pair has to compose: what List hands the panel, posted back unchanged, must
// reconstruct the original. This is the actual round trip an edit performs, and it is
// the property that would break if masking ever blanked instead of removed.
func TestMaskThenMergeRoundTrip(t *testing.T) {
	stored := json.RawMessage(`{"endpoint":"1.2.3.4:51820","privateKey":"SECRET","password":"hunter2","mtu":1420}`)

	masked := maskVpnOutSecrets("testsecret", stored)
	if strings.Contains(string(masked), "SECRET") || strings.Contains(string(masked), "hunter2") {
		t.Fatalf("a secret reached the panel: %s", masked)
	}

	// The panel edits one visible field and posts back exactly what it was given.
	var obj map[string]any
	if err := json.Unmarshal(masked, &obj); err != nil {
		t.Fatal(err)
	}
	obj["mtu"] = 1380
	edited, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(mergeKeptSettings(edited, stored), &got); err != nil {
		t.Fatal(err)
	}
	if got["privateKey"] != "SECRET" || got["password"] != "hunter2" {
		t.Errorf("secrets did not survive the round trip: %v", got)
	}
	if got["mtu"] != float64(1380) {
		t.Errorf("mtu = %v, want the edit to have taken", got["mtu"])
	}
}
