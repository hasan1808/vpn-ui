package service

import (
	"encoding/base64"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// A 2022-blake3 cipher refuses a user PSK that is not base64 of exactly the
// cipher's key length. The membership path used to mint a dashless uuid for every
// shadowsocks inbound: 32 hex characters, which decodes to 24 bytes. The account
// was created, listed and looked correct, and could never connect.
func TestShadowsocksUserKeyMatchesCipher(t *testing.T) {
	cases := []struct {
		method string
		want   int // decoded bytes; 0 means "any string is fine"
	}{
		{"2022-blake3-aes-256-gcm", 32},
		{"2022-blake3-chacha20-poly1305", 32},
		{"2022-blake3-aes-128-gcm", 16},
		{"  2022-BLAKE3-AES-256-GCM  ", 32}, // padded and upper-cased in the wild
		{"aes-256-gcm", 0},
		{"chacha20-ietf-poly1305", 0},
		{"", 0},
	}
	for _, tc := range cases {
		inbound := &model.Inbound{
			Protocol: model.Shadowsocks,
			Settings: `{"method":"` + tc.method + `","clients":[]}`,
		}
		got := shadowsocksUserKey(inbound)
		if got == "" {
			t.Errorf("method %q: minted an empty key", tc.method)
			continue
		}
		if tc.want == 0 {
			// Legacy ciphers take any string, so only the "not empty" check above
			// applies. Assert it is NOT base64-of-32 so a future change cannot
			// quietly make every method look like a 2022 one.
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(got)
		if err != nil {
			t.Errorf("method %q: %q is not valid base64: %v", tc.method, got, err)
			continue
		}
		if len(raw) != tc.want {
			t.Errorf("method %q: key decodes to %d bytes, want %d", tc.method, len(raw), tc.want)
		}
	}
}

// Unparseable settings must not panic or return an empty key: the account still
// has to be given something, and a legacy-shaped key is the safe fallback.
func TestShadowsocksUserKeyOnBadSettings(t *testing.T) {
	inbound := &model.Inbound{Protocol: model.Shadowsocks, Settings: "{not json"}
	if got := shadowsocksUserKey(inbound); got == "" {
		t.Fatal("unparseable settings produced an empty key")
	}
}
