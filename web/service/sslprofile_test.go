package service

import (
	"path/filepath"
	"strings"
	"testing"
)

// The name becomes a directory holding private keys and is chosen over HTTP, so
// anything that could climb out of the profiles directory has to be refused
// outright rather than sanitised into something else.
func TestNormalizeSSLProfileRefusesUnsafeNames(t *testing.T) {
	for _, name := range []string{
		"../escape", "a/b", `a\b`, "a b", "..", ".", "Sub Name!", "a.b",
		strings.Repeat("x", 33),
	} {
		if got, err := NormalizeSSLProfile(name); err == nil {
			t.Errorf("NormalizeSSLProfile(%q) = %q with no error, want a refusal", name, got)
		}
	}
}

func TestNormalizeSSLProfileAccepts(t *testing.T) {
	tests := map[string]string{
		"":         SSLDefaultProfile,
		"   ":      SSLDefaultProfile,
		"default":  SSLDefaultProfile,
		"DEFAULT":  SSLDefaultProfile,
		"sub":      "sub",
		"Sub":      "sub",
		" panel ":  "panel",
		"sub-2026": "sub-2026",
		"my_cert":  "my_cert",
	}
	for in, want := range tests {
		got, err := NormalizeSSLProfile(in)
		if err != nil {
			t.Errorf("NormalizeSSLProfile(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeSSLProfile(%q) = %q, want %q", in, got, want)
		}
	}
}

// The default profile MUST keep the original root. Existing installs already have
// webCertFile pointing into it, and moving it would take TLS down on the next
// restart for no gain.
func TestSSLProfileRootKeepsTheDefaultWhereItWas(t *testing.T) {
	root, err := SSLProfileRoot("")
	if err != nil {
		t.Fatal(err)
	}
	if root != DefaultSSLStoreRoot() {
		t.Errorf("default profile root = %q, want the original store root %q", root, DefaultSSLStoreRoot())
	}
	named, err := SSLProfileRoot("default")
	if err != nil {
		t.Fatal(err)
	}
	if named != root {
		t.Errorf("%q and the empty name must resolve to one store, got %q and %q", "default", named, root)
	}
}

// A named profile is a SIBLING of the default root, never a child of it: nested,
// it would sit inside a directory whose contents the store walks, and a profile
// could be mistaken for a version.
func TestSSLProfileRootIsNotNestedInTheDefaultStore(t *testing.T) {
	root, err := SSLProfileRoot("sub")
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(DefaultSSLStoreRoot(), root)
	if err == nil && !strings.HasPrefix(rel, "..") {
		t.Errorf("named profile root %q sits inside the default store %q", root, DefaultSSLStoreRoot())
	}
	if filepath.Base(root) != "sub" {
		t.Errorf("named profile root %q does not end in the profile name", root)
	}
}

// Two profiles must not share a store, or issuing for one would overwrite the
// other's active certificate.
func TestSSLProfileRootsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, name := range []string{"", "default", "sub", "panel", "extra"} {
		root, err := SSLProfileRoot(name)
		if err != nil {
			t.Fatal(err)
		}
		if prev, ok := seen[root]; ok && prev != name && !(prev == "" && name == "default") {
			t.Errorf("profiles %q and %q share the store %q", prev, name, root)
		}
		seen[root] = name
	}
}

// The default profile is never deletable: it is where a first issuance lands, and
// removing it would leave the page with nothing to select.
func TestDeleteSSLProfileRefusesTheDefault(t *testing.T) {
	for _, name := range []string{"", "default", "DEFAULT"} {
		if err := DeleteSSLProfile(name); err == nil {
			t.Errorf("DeleteSSLProfile(%q) succeeded, want a refusal", name)
		}
	}
}

func TestSamePathIgnoresAnEmptySetting(t *testing.T) {
	if samePath("", "/x/active/fullchain.pem") {
		t.Error("an unset certificate path must not count as using a profile")
	}
	if !samePath("/x/./active/fullchain.pem", "/x/active/fullchain.pem") {
		t.Error("the same path spelled two ways must compare equal")
	}
	if samePath("/y/active/fullchain.pem", "/x/active/fullchain.pem") {
		t.Error("different paths must not compare equal")
	}
}
