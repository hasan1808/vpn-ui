package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// A name the operator gives a certificate.
//
// WHY, when a certificate already has names on it. The names are the CA's: they
// are what the certificate covers, and they are often long, similar to each other,
// or an IP address. A host holding four of them ends up with four rows whose first
// column reads panel.example.com, sub.example.com, cdn.example.com, 203.0.113.10,
// and telling them apart at a glance means reading to the end of each. A nickname
// is the operator's own label for the one thing the certificate is FOR, and it sits
// beside the real names rather than replacing them, so nothing becomes ambiguous.
//
// Stored beside the auto-renew marker, in the store root, for the same reasons
// spelled out in sslautorenew.go: the profile listing has to work with no database,
// and deleting a certificate is one RemoveAll of its directory, so a settings row
// would outlive the thing it described and the next certificate to reuse that slug
// would inherit a stranger's label.

// sslNicknameFile holds the operator's label for a certificate.
const sslNicknameFile = "nickname"

// sslNicknameMax is the longest label this accepts. Long enough for a sentence
// fragment, short enough that a table column stays a table column.
const sslNicknameMax = 48

// SSLNickname returns the operator's label for a profile, or "" when it has none.
func SSLNickname(profile string) string {
	root, err := SSLProfileRoot(profile)
	if err != nil {
		return ""
	}
	return sslNicknameAt(root)
}

func sslNicknameAt(root string) string {
	b, err := os.ReadFile(filepath.Join(root, sslNicknameFile))
	if err != nil {
		return ""
	}
	// Sanitised on the way OUT as well as in, so a file edited by hand cannot put
	// control characters into every page that renders the table.
	return sslCleanNickname(string(b))
}

// SetSSLNickname sets or clears a profile's label. An empty value removes it, so
// clearing the field in the UI leaves the store as it was rather than parking an
// empty file in it.
func SetSSLNickname(profile, nickname string) error {
	_, root, err := sslResolveProfile(profile)
	if err != nil {
		return err
	}
	clean := sslCleanNickname(nickname)
	path := filepath.Join(root, sslNicknameFile)

	if clean == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clearing the nickname: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("saving the nickname: %w", err)
	}
	if err := os.WriteFile(path, []byte(clean+"\n"), 0o600); err != nil {
		return fmt.Errorf("saving the nickname: %w", err)
	}
	return nil
}

// sslCleanNickname makes a label safe to store and to render.
//
// Strips control characters rather than rejecting them: this is a free-text label,
// and refusing a paste that happened to carry a newline would be a worse experience
// than quietly taking the text without it. Length is counted in RUNES, so a label
// in Persian or Chinese gets the same 48 characters as one in English rather than
// being cut a third of the way in by a byte count.
func sslCleanNickname(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			b.WriteRune(' ')
			continue
		}
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	// Collapse the runs a stripped newline may have left behind.
	out = strings.Join(strings.Fields(out), " ")

	runes := []rune(out)
	if len(runes) > sslNicknameMax {
		out = strings.TrimSpace(string(runes[:sslNicknameMax]))
	}
	return out
}
