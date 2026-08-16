package service

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
)

// uiSettingsBlobs is the spec fixture: for each protocol whose settings JSON the
// browser builds, the exact object Inbound.<X>Settings.toJson() produces for a NEW
// inbound. Keys are in the JS toJson() order and values come from the JS CONSTRUCTOR,
// so each entry can be read side by side with its class in
// web/assets/js/model/inbound.js.
//
// It is load-bearing twice over:
//
//   - TestDefaultSettingsForMatchesTheBrowserModel compares it against
//     DefaultSettingsFor, so a key spelled differently in protocoldefaults.go (the
//     silent-breakage case: the value lands under a name nothing reads) fails here.
//   - TestFillSettingsDefaultsLeavesAFullBodyByteIdentical feeds it through
//     FillSettingsDefaults and demands the SAME STRING back, which only holds if the
//     server-side table is a subset of what the UI already sends AND nothing was
//     re-marshalled. Key order here is deliberately not alphabetical for that reason: a
//     re-marshal would sort it and the string comparison would fail.
//
// The two IPsec pre-shared keys are minted per inbound, so they carry a fixed stand-in
// of the right length and are compared by length instead (see randomSettingKeys).
var uiSettingsBlobs = map[model.Protocol]string{
	model.L2TP: `{
  "ipsecEnable": true,
  "ipsecPsk": "0123456789abcdef",
  "allowRaw": false,
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "dns1": "8.8.8.8",
  "dns2": "8.8.4.4",
  "mtu": 1400,
  "userLimit": 1,
  "userLimitStrategy": "accept",
  "clients": [],
  "externalProxy": []
}`,

	model.PPTP: `{
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "dns1": "8.8.8.8",
  "dns2": "8.8.4.4",
  "mtu": 1400,
  "userLimit": 1,
  "userLimitStrategy": "accept",
  "clients": [],
  "externalProxy": []
}`,

	model.OPENVPN: `{
  "udpEnable": true,
  "tcpEnable": true,
  "tcpPort": 1194,
  "separatePorts": false,
  "tlsUseFile": false,
  "caCertFile": "",
  "serverCertFile": "",
  "serverKeyFile": "",
  "tlsCryptFile": "",
  "dns1": "8.8.8.8",
  "dns2": "8.8.4.4",
  "mtu": 1500,
  "caCert": "",
  "caKey": "",
  "serverCert": "",
  "serverKey": "",
  "tlsCrypt": "",
  "clients": [],
  "externalProxy": [],
  "cipherMode": "all",
  "ciphers": [
    "AES-256-GCM",
    "AES-128-GCM",
    "CHACHA20-POLY1305",
    "AES-256-CBC",
    "AES-192-CBC",
    "AES-128-CBC",
    "BF-CBC",
    "DES-EDE3-CBC"
  ],
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "userLimit": 1,
  "userLimitStrategy": "accept"
}`,

	model.OPENCONNECT: `{
  "dns1": "8.8.8.8",
  "dns2": "8.8.4.4",
  "mtu": 1420,
  "tlsUseFile": false,
  "certificateFile": "",
  "keyFile": "",
  "certificate": "",
  "key": "",
  "caCert": "",
  "clients": [],
  "externalProxy": [],
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "userLimit": 1,
  "userLimitStrategy": "accept"
}`,

	model.SSTP: `{
  "dns1": "8.8.8.8",
  "dns2": "8.8.4.4",
  "mtu": 1420,
  "tlsUseFile": false,
  "certificateFile": "",
  "keyFile": "",
  "certificate": "",
  "key": "",
  "caCert": "",
  "clients": [],
  "externalProxy": [],
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "userLimit": 1,
  "userLimitStrategy": "accept"
}`,

	model.IKEV2: `{
  "dns1": "8.8.8.8",
  "dns2": "8.8.4.4",
  "mtu": 1420,
  "authMode": "eap-mschapv2",
  "psk": "",
  "serverAddr": "",
  "nattPort": 4500,
  "tlsUseFile": false,
  "certificateFile": "",
  "keyFile": "",
  "certificate": "",
  "key": "",
  "caCert": "",
  "clients": [],
  "externalProxy": [],
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "userLimit": 1,
  "userLimitStrategy": "accept"
}`,

	model.WGC: `{
  "dns1": "1.1.1.1",
  "dns2": "1.0.0.1",
  "mtu": 1420,
  "serverPrivKey": "",
  "serverPubKey": "",
  "pskEnable": false,
  "clients": [],
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "userLimit": 1,
  "userLimitStrategy": "accept",
  "externalProxy": []
}`,

	model.AWG: `{
  "dns1": "1.1.1.1",
  "dns2": "1.0.0.1",
  "mtu": 1420,
  "jc": 4,
  "jmin": 8,
  "jmax": 80,
  "s1": 77,
  "s2": 90,
  "h1": "",
  "h2": "",
  "h3": "",
  "h4": "",
  "serverPrivKey": "",
  "serverPubKey": "",
  "pskEnable": false,
  "clients": [],
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "userLimit": 1,
  "userLimitStrategy": "accept",
  "externalProxy": []
}`,

	model.GRE: `{
  "mtu": 0,
  "ttl": 64,
  "ipsecEnable": false,
  "ipsecPsk": "0123456789abcdef01234567",
  "allowRaw": true,
  "fouEnable": false,
  "fouPort": 15547,
  "clients": [],
  "clientToClient": false,
  "crossInbound": false,
  "ipRanges": [],
  "userLimit": 1,
  "userLimitStrategy": "accept"
}`,

	model.MTPROTO: `{
  "clients": []
}`,

	model.SSH: `{
  "userLimit": 0,
  "userLimitStrategy": "accept",
  "externalProxy": [],
  "clients": [],
  "hostKey": ""
}`,

	model.ANYTLS: `{
  "clients": [],
  "paddingScheme": [
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000"
  ]
}`,

	model.TUIC: `{
  "clients": [],
  "congestionControl": "cubic",
  "authTimeout": 3,
  "zeroRttHandshake": false,
  "heartbeat": 10,
  "udpTimeout": 60
}`,

	model.NAIVE: `{
  "clients": [],
  "network": "tcp",
  "masquerade": {
    "type": "404",
    "file": "",
    "url": "",
    "string": ""
  }
}`,
}

// randomSettingKeys lists the fields minted per inbound, which can only be compared by
// length. Both are IPsec pre-shared keys: RandomUtil.randomSeq(16) for L2TP and
// randomSeq(24) for GRE.
var randomSettingKeys = map[model.Protocol]map[string]int{
	model.L2TP: {"ipsecPsk": 16},
	model.GRE:  {"ipsecPsk": 24},
}

// vpnDefaultProtocols is every protocol this file is expected to know, so a new one
// added to the tables without a fixture (or the reverse) is caught rather than skipped.
var vpnDefaultProtocols = []model.Protocol{
	model.L2TP, model.PPTP, model.OPENVPN, model.OPENCONNECT, model.SSTP, model.IKEV2,
	model.WGC, model.AWG, model.GRE, model.MTPROTO, model.SSH,
	model.ANYTLS, model.TUIC, model.NAIVE,
}

func TestDefaultSettingsForMatchesTheBrowserModel(t *testing.T) {
	if len(uiSettingsBlobs) != len(vpnDefaultProtocols) {
		t.Fatalf("fixture covers %d protocols, expected %d", len(uiSettingsBlobs), len(vpnDefaultProtocols))
	}
	for _, protocol := range vpnDefaultProtocols {
		t.Run(string(protocol), func(t *testing.T) {
			blob, ok := uiSettingsBlobs[protocol]
			if !ok {
				t.Fatalf("no browser-model fixture for %s", protocol)
			}
			want := decodeSettingsMap(t, blob)
			got := decodeSettingsMap(t, mustDefaultSettings(t, protocol))

			// The minted secrets can only be checked for shape, so pull them out of
			// both sides after asserting the length the JS constructor asks for.
			for key, length := range randomSettingKeys[protocol] {
				value, ok := got[key].(string)
				if !ok {
					t.Fatalf("%q is missing or not a string in the generated defaults", key)
				}
				if len(value) != length {
					t.Errorf("%q is %d chars, want %d (RandomUtil.randomSeq(%d))", key, len(value), length, length)
				}
				delete(got, key)
				delete(want, key)
			}

			for _, problem := range settingsDiff(want, got) {
				t.Error(problem)
			}
		})
	}
}

// The minted secrets must differ per inbound. A package-level constant would satisfy
// every other test in this file and hand the same IPsec PSK to every L2TP inbound the
// panel ever creates.
func TestDefaultSettingsForMintsAFreshSecretPerCall(t *testing.T) {
	for _, protocol := range []model.Protocol{model.L2TP, model.GRE} {
		first := decodeSettingsMap(t, mustDefaultSettings(t, protocol))
		second := decodeSettingsMap(t, mustDefaultSettings(t, protocol))
		if first["ipsecPsk"] == second["ipsecPsk"] {
			t.Errorf("%s: two inbounds got the same ipsecPsk %q", protocol, first["ipsecPsk"])
		}
	}
}

// The defaults have to unmarshal into the struct the protocol's own service parses the
// same blob with, carrying the values through. This is the check that catches a key
// name that is plausible but wrong: json.Unmarshal ignores what it does not recognise,
// so a misspelled key leaves the field on its zero value and nothing complains.
func TestDefaultSettingsForRoundTripsIntoTheProtocolStruct(t *testing.T) {
	t.Run("l2tp", func(t *testing.T) {
		var s l2tpSettings
		unmarshalDefaults(t, model.L2TP, &s)
		if !s.IpsecEnable || len(s.IpsecPsk) != 16 || s.AllowRaw {
			t.Errorf("ipsec block: enable=%v psk=%d chars allowRaw=%v", s.IpsecEnable, len(s.IpsecPsk), s.AllowRaw)
		}
		if s.Dns1 != "8.8.8.8" || s.Dns2 != "8.8.4.4" || s.Mtu != 1400 {
			t.Errorf("dns/mtu: %q %q %d", s.Dns1, s.Dns2, s.Mtu)
		}
		if effectiveUserLimit(s.UserLimit) != 1 || s.UserLimitStrategy != "accept" {
			t.Errorf("user limit: %v %q", s.UserLimit, s.UserLimitStrategy)
		}
	})

	t.Run("pptp", func(t *testing.T) {
		var s pptpSettings
		unmarshalDefaults(t, model.PPTP, &s)
		if s.Dns1 != "8.8.8.8" || s.Dns2 != "8.8.4.4" || s.Mtu != 1400 {
			t.Errorf("dns/mtu: %q %q %d", s.Dns1, s.Dns2, s.Mtu)
		}
		if effectiveUserLimit(s.UserLimit) != 1 || s.UserLimitStrategy != "accept" {
			t.Errorf("user limit: %v %q", s.UserLimit, s.UserLimitStrategy)
		}
	})

	t.Run("openvpn", func(t *testing.T) {
		var s openvpnSettings
		unmarshalDefaults(t, model.OPENVPN, &s)
		if s.UdpEnable == nil || !*s.UdpEnable || s.TcpEnable == nil || !*s.TcpEnable {
			t.Errorf("transports: udp=%v tcp=%v", s.UdpEnable, s.TcpEnable)
		}
		if s.TcpPort != 1194 || s.SeparatePorts == nil || *s.SeparatePorts {
			t.Errorf("tcp port/separatePorts: %d %v", s.TcpPort, s.SeparatePorts)
		}
		if s.Mtu != 1500 || s.CipherMode != "all" || len(s.Ciphers) != 8 {
			t.Errorf("mtu/ciphers: %d %q %d ciphers", s.Mtu, s.CipherMode, len(s.Ciphers))
		}
		if s.Ciphers[0] != "AES-256-GCM" || s.Ciphers[len(s.Ciphers)-1] != "DES-EDE3-CBC" {
			t.Errorf("cipher order is the data-ciphers preference order: %v", s.Ciphers)
		}
	})

	t.Run("openconnect", func(t *testing.T) {
		var s ocservSettings
		unmarshalDefaults(t, model.OPENCONNECT, &s)
		if s.Dns1 != "8.8.8.8" || s.Mtu != 1420 || s.TlsUseFile {
			t.Errorf("dns/mtu/tls: %q %d %v", s.Dns1, s.Mtu, s.TlsUseFile)
		}
		if effectiveUserLimit(s.UserLimit) != 1 || s.UserLimitStrategy != "accept" {
			t.Errorf("user limit: %v %q", s.UserLimit, s.UserLimitStrategy)
		}
	})

	t.Run("sstp", func(t *testing.T) {
		var s sstpSettings
		unmarshalDefaults(t, model.SSTP, &s)
		if s.Dns1 != "8.8.8.8" || s.Mtu != 1420 || s.TlsUseFile {
			t.Errorf("dns/mtu/tls: %q %d %v", s.Dns1, s.Mtu, s.TlsUseFile)
		}
	})

	t.Run("ikev2", func(t *testing.T) {
		var s ikev2Settings
		unmarshalDefaults(t, model.IKEV2, &s)
		if s.authMode() != "eap-mschapv2" || s.Psk != "" || s.ServerAddr != "" {
			t.Errorf("auth block: %q psk=%q addr=%q", s.authMode(), s.Psk, s.ServerAddr)
		}
		if s.Dns1 != "8.8.8.8" || s.Dns2 != "8.8.4.4" {
			t.Errorf("dns: %q %q", s.Dns1, s.Dns2)
		}
	})

	t.Run("wg-c", func(t *testing.T) {
		var s wgcSettings
		unmarshalDefaults(t, model.WGC, &s)
		// The WireGuard family resolves its own DNS pair, which is NOT the PPP
		// family's 8.8.8.8: it is written into the generated client config.
		if s.Dns1 != "1.1.1.1" || s.Dns2 != "1.0.0.1" || s.Mtu != 1420 {
			t.Errorf("dns/mtu: %q %q %d", s.Dns1, s.Dns2, s.Mtu)
		}
		if s.ServerPrivKey != "" || s.ServerPubKey != "" || s.PskEnable {
			t.Errorf("key material must be left to ReconcileKeys: %q %q %v", s.ServerPrivKey, s.ServerPubKey, s.PskEnable)
		}
	})

	t.Run("awg", func(t *testing.T) {
		var s awgSettings
		unmarshalDefaults(t, model.AWG, &s)
		if s.Dns1 != "1.1.1.1" || s.Dns2 != "1.0.0.1" || s.Mtu != 1420 {
			t.Errorf("dns/mtu: %q %q %d", s.Dns1, s.Dns2, s.Mtu)
		}
		for name, got := range map[string]*int{"jc": s.Jc, "jmin": s.Jmin, "jmax": s.Jmax, "s1": s.S1, "s2": s.S2} {
			if got == nil {
				t.Fatalf("%s did not survive into awgSettings", name)
			}
		}
		if *s.Jc != 4 || *s.Jmin != 8 || *s.Jmax != 80 || *s.S1 != 77 || *s.S2 != 90 {
			t.Errorf("obfuscation params: jc=%d jmin=%d jmax=%d s1=%d s2=%d", *s.Jc, *s.Jmin, *s.Jmax, *s.S1, *s.S2)
		}
	})

	t.Run("gre", func(t *testing.T) {
		var s greSettings
		unmarshalDefaults(t, model.GRE, &s)
		if s.Mtu != 0 || s.Ttl != 64 {
			t.Errorf("mtu must stay 0 (kernel picks per encapsulation), ttl 64: %d %d", s.Mtu, s.Ttl)
		}
		if s.IpsecEnable || !s.AllowRaw || len(s.IpsecPsk) != 24 {
			t.Errorf("ipsec block: enable=%v allowRaw=%v psk=%d chars", s.IpsecEnable, s.AllowRaw, len(s.IpsecPsk))
		}
		if s.FouEnable || s.FouPort != 15547 {
			t.Errorf("fou: enable=%v port=%d", s.FouEnable, s.FouPort)
		}
	})

	t.Run("ssh", func(t *testing.T) {
		var s sshSettings
		unmarshalDefaults(t, model.SSH, &s)
		// 0 is the constructor's value and means NO limit. It has to arrive as an
		// explicit 0 rather than an absent key, which effectiveSshK reads as 1.
		if s.UserLimit == nil || *s.UserLimit != 0 {
			t.Errorf("userLimit must be an explicit 0 (no limit), got %v", s.UserLimit)
		}
		if s.UserLimitStrategy != "accept" || s.HostKey != "" {
			t.Errorf("strategy/hostKey: %q %q", s.UserLimitStrategy, s.HostKey)
		}
	})

	t.Run("mtproto", func(t *testing.T) {
		var s mtprotoSettings
		unmarshalDefaults(t, model.MTPROTO, &s)
		if s.Clients == nil {
			t.Error("clients must be an empty array, not absent")
		}
	})
}

// A protocol whose settings the core owns must be left completely alone: inventing keys
// for a vmess inbound could only corrupt a config Xray already understands.
func TestXrayNativeProtocolsAreNotDefaulted(t *testing.T) {
	for _, protocol := range []model.Protocol{model.VMESS, model.VLESS, model.Trojan, model.Shadowsocks} {
		if _, err := DefaultSettingsFor(protocol); err == nil {
			t.Errorf("%s: DefaultSettingsFor should refuse a protocol it has no shape for", protocol)
		}
		posted := `{"clients":[{"id":"x"}],"decryption":"none"}`
		got, err := FillSettingsDefaults(protocol, posted)
		if err != nil {
			t.Fatalf("%s: FillSettingsDefaults: %v", protocol, err)
		}
		if got != posted {
			t.Errorf("%s: settings were rewritten\n got: %s\nwant: %s", protocol, got, posted)
		}
		if err := ValidateProtocolSettings(protocol, posted); err != nil {
			t.Errorf("%s: ValidateProtocolSettings should not judge a core-owned shape: %v", protocol, err)
		}
	}
}

// The constraint the whole feature hangs on: every request the panel's UI makes today
// already carries the full shape, and those must store the SAME BYTES they did before
// defaults existed. Literal string comparison, against a fixture whose keys are in the
// browser's order rather than sorted, so a re-marshal cannot pass unnoticed.
func TestFillSettingsDefaultsLeavesAFullBodyByteIdentical(t *testing.T) {
	for _, protocol := range vpnDefaultProtocols {
		t.Run(string(protocol), func(t *testing.T) {
			posted := uiSettingsBlobs[protocol]
			got, err := FillSettingsDefaults(protocol, posted)
			if err != nil {
				t.Fatalf("FillSettingsDefaults: %v", err)
			}
			if got != posted {
				t.Errorf("a full body was rewritten\n got: %s\nwant: %s", got, posted)
			}
		})
	}
}

func TestFillSettingsDefaultsNeverOverwritesWhatTheCallerSent(t *testing.T) {
	// Every value here is deliberately NOT the default, including the ones that are
	// falsy: `false` and `0` are values the caller chose, and treating them as "absent"
	// is the classic way a defaults layer silently overrides an explicit choice.
	posted := `{
		"ipsecEnable": false,
		"ipsecPsk": "operator-chosen-secret",
		"dns1": "9.9.9.9",
		"mtu": 1280,
		"userLimit": 0,
		"userLimitStrategy": "reject",
		"clients": [{"id": "alice", "password": "pw", "email": "alice@example.com"}]
	}`
	filled, err := FillSettingsDefaults(model.L2TP, posted)
	if err != nil {
		t.Fatalf("FillSettingsDefaults: %v", err)
	}
	got := decodeSettingsMap(t, filled)

	for key, want := range map[string]any{
		"ipsecEnable":       false,
		"ipsecPsk":          "operator-chosen-secret",
		"dns1":              "9.9.9.9",
		"mtu":               float64(1280),
		"userLimit":         float64(0),
		"userLimitStrategy": "reject",
	} {
		if !reflect.DeepEqual(got[key], want) {
			t.Errorf("%q was overwritten: got %#v, want %#v", key, got[key], want)
		}
	}
	// ...and the keys that were absent were filled from the protocol's shape.
	for key, want := range map[string]any{
		"dns2":           "8.8.4.4",
		"allowRaw":       false,
		"clientToClient": false,
		"crossInbound":   false,
	} {
		if !reflect.DeepEqual(got[key], want) {
			t.Errorf("%q was not defaulted: got %#v, want %#v", key, got[key], want)
		}
	}
	if _, ok := got["ipRanges"]; !ok {
		t.Error("ipRanges was not defaulted")
	}
	clients, _ := got["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("the posted client list was replaced: %#v", got["clients"])
	}
}

// The minimal API body this whole file exists for: no settings at all.
func TestFillSettingsDefaultsFromNothing(t *testing.T) {
	for _, posted := range []string{"", "   ", "{}", "null"} {
		filled, err := FillSettingsDefaults(model.WGC, posted)
		if err != nil {
			t.Fatalf("FillSettingsDefaults(%q): %v", posted, err)
		}
		got := decodeSettingsMap(t, filled)
		want := decodeSettingsMap(t, mustDefaultSettings(t, model.WGC))
		for _, problem := range settingsDiff(want, got) {
			t.Errorf("posted %q: %s", posted, problem)
		}
	}
}

func TestFillSettingsDefaultsRejectsNonObjectSettings(t *testing.T) {
	for _, posted := range []string{`[1,2]`, `"a string"`, `{"broken":`} {
		if _, err := FillSettingsDefaults(model.L2TP, posted); err == nil {
			t.Errorf("posted %q was accepted as a settings object", posted)
		}
	}
}

func TestValidateProtocolSettings(t *testing.T) {
	tests := []struct {
		name     string
		protocol model.Protocol
		settings string
		// wantErr is a substring the message must carry, so a check that fires for the
		// wrong reason is not mistaken for the one under test. Empty means "accepted".
		wantErr string
	}{
		{"l2tp defaults are valid", model.L2TP, uiSettingsBlobs[model.L2TP], ""},
		{"gre defaults are valid", model.GRE, uiSettingsBlobs[model.GRE], ""},
		{"naive defaults are valid", model.NAIVE, uiSettingsBlobs[model.NAIVE], ""},

		{"cleared mtu box", model.L2TP, `{"mtu":""}`, `"mtu" must be a number`},
		{"mtu as a numeric string", model.L2TP, `{"mtu":"1400"}`, `"mtu" must be a number`},
		{"mtu below the IPv4 floor", model.L2TP, `{"mtu":100}`, `"mtu"`},
		{"mtu 0 means protocol default", model.L2TP, `{"mtu":0}`, ""},
		{"dns hostname", model.PPTP, `{"dns1":"dns.example.com"}`, `"dns1" must be an IP address`},
		{"dns empty is the daemon default", model.PPTP, `{"dns1":""}`, ""},

		{"user limit over the cap", model.WGC, `{"userLimit":65}`, `"userLimit"`},
		{"user limit negative", model.WGC, `{"userLimit":-1}`, `"userLimit"`},
		{"user limit 0 is no limit", model.WGC, `{"userLimit":0}`, ""},
		{"strategy typo", model.SSTP, `{"userLimitStrategy":"Accept"}`, `"userLimitStrategy"`},

		// The pool format is the allocator's own "A.B.C.s-A.B.C.e", NOT a CIDR, and
		// parseRange drops anything else without a word.
		{"ip range as a CIDR", model.OPENCONNECT, `{"ipRanges":["10.4.0.0/24"]}`, `"ipRanges"`},
		{"ip range spanning two /24s", model.OPENCONNECT, `{"ipRanges":["10.4.0.2-10.4.1.254"]}`, `"ipRanges"`},
		{"ip range backwards", model.OPENCONNECT, `{"ipRanges":["10.4.0.200-10.4.0.10"]}`, `"ipRanges"`},
		{"ip range v6", model.OPENCONNECT, `{"ipRanges":["fd00::1-fd00::5"]}`, `"ipRanges"`},
		{"ip range as the allocator writes it", model.OPENCONNECT, `{"ipRanges":["10.4.0.2-10.4.0.254"]}`, ""},
		{"ip range last-octet shorthand", model.OPENCONNECT, `{"ipRanges":["10.4.0.2-254"]}`, ""},
		{"ip range blank row", model.OPENCONNECT, `{"ipRanges":["","10.4.0.2-10.4.0.254"]}`, ""},

		{"l2tp ipsec without a psk", model.L2TP, `{"ipsecEnable":true,"ipsecPsk":""}`, `"ipsecPsk" is required`},
		{"gre ipsec without a psk", model.GRE, `{"ipsecEnable":true,"ipsecPsk":"  "}`, `"ipsecPsk" is required`},
		{"gre fou without a port", model.GRE, `{"fouEnable":true,"fouPort":0}`, `"fouPort" is required`},
		{"gre ttl out of range", model.GRE, `{"ttl":300}`, `"ttl"`},

		{"openvpn tcp port out of range", model.OPENVPN, `{"tcpPort":70000}`, `"tcpPort"`},
		{"openvpn cipher mode typo", model.OPENVPN, `{"cipherMode":"modern"}`, `"cipherMode"`},
		{"openvpn with no ciphers", model.OPENVPN, `{"ciphers":[]}`, `"ciphers"`},

		{"ikev2 psk mode without a psk", model.IKEV2, `{"authMode":"psk","psk":""}`, `"psk" is required`},
		{"ikev2 auth mode typo", model.IKEV2, `{"authMode":"eap-mschap"}`, `"authMode"`},
		{"ikev2 natt port", model.IKEV2, `{"nattPort":99999}`, `"nattPort"`},

		{"awg jmin above jmax", model.AWG, `{"jmin":90,"jmax":10}`, `"jmin"`},
		{"awg negative junk count", model.AWG, `{"jc":-1}`, `"jc"`},

		{"tuic congestion typo", model.TUIC, `{"congestionControl":"cubik"}`, `"congestionControl"`},
		{"tuic negative timeout", model.TUIC, `{"udpTimeout":-5}`, `"udpTimeout"`},

		{"naive transport typo", model.NAIVE, `{"network":"tpc"}`, `"network"`},
		{"naive quic spelling", model.NAIVE, `{"network":"tcp,quic"}`, ""},
		{"naive masquerade type typo", model.NAIVE, `{"masquerade":{"type":"418"}}`, `"type"`},
		{"naive masquerade proxy with no url", model.NAIVE, `{"masquerade":{"type":"proxy","url":""}}`, `"masquerade.url" is required`},
		{"naive masquerade file with no dir", model.NAIVE, `{"masquerade":{"type":"file"}}`, `"masquerade.file" is required`},

		{"external proxy port", model.WGC, `{"externalProxy":[{"dest":"cdn.example.com","port":70000}]}`, `"externalProxy"`},
		{"clients as an object", model.L2TP, `{"clients":{"id":"a"}}`, `"clients" must be an array`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProtocolSettings(tt.protocol, tt.settings)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("rejected a valid blob: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %s, expected an error naming %s", tt.settings, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error does not name the field\n got: %v\nwant substring: %s", err, tt.wantErr)
			}
		})
	}
}

// Validation that is stricter than reality is a regression, not a safety net: it runs on
// the UI's own requests and on the E2E harness's. These blobs are copied from
// test_unit/harness/server_setup.py, the panel's existing real API client, and are also
// the partial-body shape this whole feature is meant to serve. Every one must pass.
func TestValidateProtocolSettingsAcceptsTheExistingApiClientsBodies(t *testing.T) {
	bodies := map[model.Protocol]string{
		model.L2TP: `{"ipsecEnable":true,"ipsecPsk":"e2e-psk","allowRaw":true,
			"clientToClient":true,"crossInbound":true,
			"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1400,"clients":[]}`,
		model.PPTP: `{"clientToClient":true,"crossInbound":true,
			"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1400,"clients":[]}`,
		model.OPENVPN: `{"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1500,
			"cipherMode":"all","ciphers":["AES-256-GCM","AES-128-GCM","CHACHA20-POLY1305","AES-256-CBC"],
			"clientToClient":true,"crossInbound":true,"clients":[]}`,
		model.OPENCONNECT: `{"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1420,"tlsUseFile":false,
			"certificate":"-----BEGIN CERTIFICATE-----","key":"-----BEGIN PRIVATE KEY-----",
			"clientToClient":true,"crossInbound":true,"clients":[]}`,
		model.SSTP: `{"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1400,"tlsUseFile":false,
			"certificate":"-----BEGIN CERTIFICATE-----","key":"-----BEGIN PRIVATE KEY-----",
			"clientToClient":true,"crossInbound":true,"clients":[]}`,
		model.IKEV2: `{"dns1":"1.1.1.1","dns2":"8.8.8.8","authMode":"eap-mschapv2","serverAddr":"",
			"tlsUseFile":false,"certificate":"-----BEGIN CERTIFICATE-----","key":"k","caCert":"ca",
			"clientToClient":true,"crossInbound":true,"clients":[]}`,
		model.WGC: `{"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1420,"pskEnable":false,
			"clientToClient":true,"crossInbound":true,"clients":[]}`,
		model.AWG: `{"dns1":"1.1.1.1","dns2":"8.8.8.8","mtu":1420,"pskEnable":false,
			"clientToClient":true,"crossInbound":true,"clients":[]}`,
		model.GRE: `{"mtu":0,"ttl":64,"ipsecEnable":false,"ipsecPsk":"gre-psk","allowRaw":true,
			"fouEnable":false,"fouPort":15547,"clientToClient":true,"crossInbound":true,
			"userLimit":1,"clients":[]}`,
		model.SSH:     `{"userLimit":1,"userLimitStrategy":"reject","clients":[]}`,
		model.MTPROTO: `{"clients":[]}`,
	}
	for protocol, settings := range bodies {
		t.Run(string(protocol), func(t *testing.T) {
			if err := ValidateProtocolSettings(protocol, settings); err != nil {
				t.Fatalf("rejected a body an existing API client sends today: %v", err)
			}
		})
	}
}

// End to end through the real add path: a full body (what the UI posts) must come out of
// AddInbound with exactly the keys it went in with. Defaults may only ADD.
func TestAddInboundLeavesAFullSettingsBodyAlone(t *testing.T) {
	s := newInboundDB(t)

	posted := withClients(t, uiSettingsBlobs[model.L2TP], map[string]any{
		"id": "alice", "password": "alice-pw", "email": "alice@example.com", "enable": false,
	})
	added, _, err := s.AddInbound(&model.Inbound{
		UserId: 1, Tag: "inbound-11101", Port: 11101, Protocol: model.L2TP,
		Enable: true, Settings: posted,
	})
	if err != nil {
		t.Fatalf("AddInbound: %v", err)
	}

	want := decodeSettingsMap(t, posted)
	got := decodeSettingsMap(t, readStoredSettings(t, added.Id))

	// AddInbound has always stamped created_at/updated_at and allocated a slot on the
	// way through, so the client entries are compared by count, not by content.
	wantClients, _ := want["clients"].([]any)
	gotClients, _ := got["clients"].([]any)
	if len(wantClients) != len(gotClients) {
		t.Errorf("client count changed: %d -> %d", len(wantClients), len(gotClients))
	}
	delete(want, "clients")
	delete(got, "clients")

	for _, problem := range settingsDiff(want, got) {
		t.Error(problem)
	}
}

// ...and the point of the exercise: a body carrying almost nothing creates the same
// inbound the panel's own form would.
func TestAddInboundFillsDefaultsForAMinimalBody(t *testing.T) {
	s := newInboundDB(t)

	added, _, err := s.AddInbound(&model.Inbound{
		UserId: 1, Tag: "inbound-11102", Port: 11102, Protocol: model.L2TP, Enable: true,
		Settings: `{"clients":[{"id":"bob","password":"bob-pw","email":"bob@example.com","enable":false}]}`,
	})
	if err != nil {
		t.Fatalf("AddInbound: %v", err)
	}

	var stored l2tpSettings
	if err := json.Unmarshal([]byte(readStoredSettings(t, added.Id)), &stored); err != nil {
		t.Fatalf("the stored settings do not parse as l2tpSettings: %v", err)
	}
	if stored.Dns1 != "8.8.8.8" || stored.Dns2 != "8.8.4.4" || stored.Mtu != 1400 {
		t.Errorf("dns/mtu were not defaulted: %q %q %d", stored.Dns1, stored.Dns2, stored.Mtu)
	}
	if !stored.IpsecEnable || len(stored.IpsecPsk) != 16 {
		t.Errorf("ipsec was not defaulted: enable=%v psk=%q", stored.IpsecEnable, stored.IpsecPsk)
	}
	if effectiveUserLimit(stored.UserLimit) != 1 || stored.UserLimitStrategy != "accept" {
		t.Errorf("user limit was not defaulted: %v %q", stored.UserLimit, stored.UserLimitStrategy)
	}
	if len(stored.Clients) != 1 || stored.Clients[0].ID != "bob" {
		t.Errorf("the posted client did not survive: %#v", stored.Clients)
	}
}

// The headline case, run in the controller's own order: NormalizeVpnRanges (which the
// add handler calls before AddInbound, and which parses the settings itself) followed by
// AddInbound, with NO settings at all. The defaults land after the range assignment, so
// neither step can undo the other.
func TestAddInboundFromAnEmptyBody(t *testing.T) {
	for _, tc := range []struct {
		protocol model.Protocol
		port     int
		wantDns1 string
		wantMtu  int
	}{
		{model.L2TP, 11201, "8.8.8.8", 1400},
		{model.WGC, 11202, "1.1.1.1", 1420},
	} {
		t.Run(string(tc.protocol), func(t *testing.T) {
			s := newInboundDB(t)

			inbound := &model.Inbound{
				UserId: 1, Tag: fmt.Sprintf("inbound-%d", tc.port), Port: tc.port,
				Protocol: tc.protocol, Enable: true,
			}
			if err := NormalizeVpnRanges(inbound, 0); err != nil {
				t.Fatalf("NormalizeVpnRanges: %v", err)
			}
			added, _, err := s.AddInbound(inbound)
			if err != nil {
				t.Fatalf("AddInbound: %v", err)
			}

			got := decodeSettingsMap(t, readStoredSettings(t, added.Id))
			if got["dns1"] != tc.wantDns1 {
				t.Errorf("dns1 = %#v, want %q", got["dns1"], tc.wantDns1)
			}
			if got["mtu"] != float64(tc.wantMtu) {
				t.Errorf("mtu = %#v, want %d", got["mtu"], tc.wantMtu)
			}
			if got["userLimitStrategy"] != "accept" {
				t.Errorf("userLimitStrategy = %#v", got["userLimitStrategy"])
			}
			// The pool NormalizeVpnRanges assigned has to survive the defaults pass:
			// overwriting it with the empty list would hand the inbound no addresses.
			ranges, _ := got["ipRanges"].([]any)
			if len(ranges) == 0 {
				t.Errorf("the assigned address pool was overwritten: %#v", got["ipRanges"])
			}
		})
	}
}

// A settings blob the protocol's own struct could never parse used to save cleanly and
// break at the daemon, which reports nowhere the operator can see.
func TestAddInboundRejectsUnusableSettings(t *testing.T) {
	s := newInboundDB(t)

	_, _, err := s.AddInbound(&model.Inbound{
		UserId: 1, Tag: "inbound-11103", Port: 11103, Protocol: model.L2TP, Enable: true,
		Settings: `{"mtu":"","clients":[{"id":"carol","password":"carol-pw","email":"carol@example.com","enable":false}]}`,
	})
	if err == nil {
		t.Fatal("an l2tp inbound with a non-numeric mtu was accepted")
	}
	if !strings.Contains(err.Error(), `"mtu"`) {
		t.Fatalf("the error does not name the field: %v", err)
	}
}

// model.Client is what every posted client is normalized through on the add path, and a
// field missing from it is silently dropped. wg-c/awg per-device keypairs were: the
// account came back with no devices, ReconcileKeys minted fresh ones for devices 2..K,
// and every config already handed out for them stopped authenticating with no error
// anywhere. Invisible at User Limit 1, which is why it survived.
func TestAddInboundKeepsWireguardDeviceKeys(t *testing.T) {
	for _, protocol := range []model.Protocol{model.WGC, model.AWG} {
		t.Run(string(protocol), func(t *testing.T) {
			s := newInboundDB(t)

			client := map[string]any{
				"id": "dave@example.com", "email": "dave@example.com", "enable": false,
				"privKey": "device-0-priv", "pubKey": "device-0-pub", "psk": "device-0-psk",
				"devices": []any{
					map[string]any{"privKey": "device-0-priv", "pubKey": "device-0-pub", "psk": "device-0-psk"},
					map[string]any{"privKey": "device-1-priv", "pubKey": "device-1-pub", "psk": "device-1-psk"},
				},
			}
			added, _, err := s.AddInbound(&model.Inbound{
				UserId: 1, Tag: "inbound-11104", Port: 11104, Protocol: protocol, Enable: true,
				Settings: withClients(t, uiSettingsBlobs[protocol], client),
			})
			if err != nil {
				t.Fatalf("AddInbound: %v", err)
			}

			// Read the STORED JSON as a raw map, the way wgc.go/awg.go read it, rather
			// than back through model.Client: parsing it with the very struct whose
			// missing field caused the bug would hide the bug.
			stored := decodeSettingsMap(t, readStoredSettings(t, added.Id))
			list, _ := stored["clients"].([]any)
			if len(list) != 1 {
				t.Fatalf("want 1 stored client, got %#v", stored["clients"])
			}
			got, _ := list[0].(map[string]any)
			for key, want := range map[string]any{
				"privKey": "device-0-priv", "pubKey": "device-0-pub", "psk": "device-0-psk",
			} {
				if got[key] != want {
					t.Errorf("the legacy keypair mirror was dropped: %q = %#v, want %q", key, got[key], want)
				}
			}
			want := []any{
				map[string]any{"privKey": "device-0-priv", "pubKey": "device-0-pub", "psk": "device-0-psk"},
				map[string]any{"privKey": "device-1-priv", "pubKey": "device-1-pub", "psk": "device-1-psk"},
			}
			if !reflect.DeepEqual(got["devices"], want) {
				t.Errorf("per-device key material did not survive the add path\n got: %#v\nwant: %#v", got["devices"], want)
			}
		})
	}
}

// Shadowsocks is not one of the 14 protocols this file defaults, but it shares the
// model.Client normalization on the add path, and its per-account cipher was the last
// field still missing from that struct. The core reads clients[].method and only falls
// back to the inbound's when blank (infra/conf/shadowsocks.go), so dropping an explicit
// one silently re-ciphers the account: on an SS2022 inbound it simply stops
// authenticating, and nothing is logged.
func TestAddInboundKeepsShadowsocksPerClientMethod(t *testing.T) {
	s := newInboundDB(t)

	posted := `{"method":"2022-blake3-aes-256-gcm","password":"inbound-psk","network":"tcp,udp","ivCheck":false,` +
		`"clients":[{"method":"2022-blake3-chacha20-poly1305","password":"client-psk","email":"erin@example.com","enable":false}]}`
	added, _, err := s.AddInbound(&model.Inbound{
		UserId: 1, Tag: "inbound-11301", Port: 11301, Protocol: model.Shadowsocks,
		Enable: true, Settings: posted,
	})
	if err != nil {
		t.Fatalf("AddInbound: %v", err)
	}

	// Read the stored JSON as a raw map, the way the core reads it, rather than back
	// through model.Client: parsing it with the struct whose missing field caused the
	// bug would hide the bug.
	stored := decodeSettingsMap(t, readStoredSettings(t, added.Id))
	list, _ := stored["clients"].([]any)
	if len(list) != 1 {
		t.Fatalf("want 1 stored client, got %#v", stored["clients"])
	}
	got, _ := list[0].(map[string]any)
	if got["method"] != "2022-blake3-chacha20-poly1305" {
		t.Errorf("the per-account cipher did not survive the add path: %#v", got["method"])
	}
	// The inbound-level method is not touched by the client normalization at all.
	if stored["method"] != "2022-blake3-aes-256-gcm" {
		t.Errorf("the inbound-level method changed: %#v", stored["method"])
	}
}

// Adding fields to model.Client must not put a single byte into any other protocol's
// stored client JSON, which is what the omitempty on each of them buys.
func TestClientKeyFieldsAreOmittedForOtherProtocols(t *testing.T) {
	bs, err := json.Marshal(model.Client{ID: "alice", Email: "alice@example.com", Enable: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"privKey", "pubKey", "psk", "devices", "method"} {
		if strings.Contains(string(bs), `"`+key+`"`) {
			t.Errorf("a plain client grew a %q key: %s", key, bs)
		}
	}
}

// --- helpers -----------------------------------------------------------------------

func mustDefaultSettings(t *testing.T, protocol model.Protocol) string {
	t.Helper()
	settings, err := DefaultSettingsFor(protocol)
	if err != nil {
		t.Fatalf("DefaultSettingsFor(%s): %v", protocol, err)
	}
	return settings
}

func unmarshalDefaults(t *testing.T, protocol model.Protocol, into any) {
	t.Helper()
	if err := json.Unmarshal([]byte(mustDefaultSettings(t, protocol)), into); err != nil {
		t.Fatalf("the %s defaults do not parse into its own settings struct: %v", protocol, err)
	}
}

func decodeSettingsMap(t *testing.T, settings string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal([]byte(settings), &root); err != nil {
		t.Fatalf("decode settings: %v\n%s", err, settings)
	}
	return root
}

// settingsDiff reports every way got departs from want, one line each, so a mismatch
// names the key rather than dumping two objects to eyeball.
func settingsDiff(want, got map[string]any) []string {
	var problems []string
	for _, key := range sortedKeys(want) {
		gotValue, ok := got[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("missing key %q", key))
			continue
		}
		if !reflect.DeepEqual(want[key], gotValue) {
			problems = append(problems, fmt.Sprintf("key %q: got %#v, want %#v", key, gotValue, want[key]))
		}
	}
	for _, key := range sortedKeys(got) {
		if _, ok := want[key]; !ok {
			problems = append(problems, fmt.Sprintf("unexpected key %q (value %#v)", key, got[key]))
		}
	}
	return problems
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// withClients replaces a fixture's empty client list, so the add-path tests exercise
// the same blob the UI would post rather than an accountless one.
func withClients(t *testing.T, settings string, clients ...map[string]any) string {
	t.Helper()
	root := decodeSettingsMap(t, settings)
	list := make([]any, 0, len(clients))
	for _, c := range clients {
		list = append(list, c)
	}
	root["clients"] = list
	bs, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("marshal settings with clients: %v", err)
	}
	return string(bs)
}

func readStoredSettings(t *testing.T, inboundId int) string {
	t.Helper()
	var inbound model.Inbound
	if err := database.GetDB().Model(model.Inbound{}).Where("id = ?", inboundId).First(&inbound).Error; err != nil {
		t.Fatalf("read inbound %d: %v", inboundId, err)
	}
	return inbound.Settings
}
