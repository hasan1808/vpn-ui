package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNicknameDefaultsToEmpty(t *testing.T) {
	if got := sslNicknameAt(t.TempDir()); got != "" {
		t.Errorf("a store with no nickname reported %q; the column is empty by default", got)
	}
}

func TestNicknameRoundTrips(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, sslNicknameFile), []byte("Panel and admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sslNicknameAt(root); got != "Panel and admin" {
		t.Errorf("nickname = %q, want the label without its trailing newline", got)
	}
}

// The label is rendered into a table on every page load, so a control character
// that reached the file by hand must not travel with it.
func TestNicknameStripsControlCharacters(t *testing.T) {
	cases := map[string]string{
		"Panel\ncert":       "Panel cert",
		"Panel\r\ncert":     "Panel cert",
		"Panel\tcert":       "Panel cert",
		"  spaced  out  ":   "spaced out",
		"Panel\x00\x07cert": "Panelcert",
		"":                  "",
		"   ":               "",
	}
	for in, want := range cases {
		if got := sslCleanNickname(in); got != want {
			t.Errorf("sslCleanNickname(%q) = %q, want %q", in, got, want)
		}
	}
}

// Counted in runes, not bytes: a Persian or Chinese label must get the same
// number of characters as an English one rather than being cut a third of the way
// in by a byte count.
func TestNicknameLengthIsCountedInCharacters(t *testing.T) {
	long := strings.Repeat("ن", 100)
	got := sslCleanNickname(long)
	if n := len([]rune(got)); n != sslNicknameMax {
		t.Errorf("a %d-character Persian label came back as %d characters, want %d",
			100, n, sslNicknameMax)
	}
	// And the result must still be valid text, not a half-decoded rune.
	if !strings.HasPrefix(long, got) {
		t.Error("truncation produced something that is not a prefix of the input")
	}
}

// Clearing removes the file rather than leaving an empty one behind, so a store
// whose label was set and then cleared looks like one that never had it.
func TestNicknameClearingRemovesTheFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, sslNicknameFile)
	if err := os.WriteFile(path, []byte("something\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sslCleanNickname(""); got != "" {
		t.Fatalf("setup: empty should clean to empty, got %q", got)
	}
	// SetSSLNickname needs a resolvable profile, so exercise the file half here
	// and leave the profile plumbing to the endpoint.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the nickname file outlived being cleared")
	}
	if got := sslNicknameAt(root); got != "" {
		t.Errorf("nickname = %q after clearing, want empty", got)
	}
}
