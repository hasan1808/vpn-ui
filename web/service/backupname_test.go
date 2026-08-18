package service

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/config"
)

// filenameGate mirrors web/controller/server.go's isValidFilename, the check
// /getDb applies to whatever this builder produces. Duplicated rather than
// imported because the controller imports the service and not the other way
// round; a change to one that is not made to the other should fail here.
var filenameGate = regexp.MustCompile(`^[a-zA-Z0-9_\-.]+$`)

// PanelName and Domain are left out of every case that asserts an exact name:
// resolving them reads the settings table, and these tests run without a DB.

func TestBuildBackupFilenameNothingTicked(t *testing.T) {
	var s ServerService
	if got := s.BuildBackupFilename(BackupNameOptions{}, "panel.example.com"); got != "vpn-ui.db" {
		t.Errorf("all components off = %q; want vpn-ui.db", got)
	}
}

func TestBuildBackupFilenameComponents(t *testing.T) {
	var s ServerService
	date := regexp.MustCompile(`^vpn-ui_\d{8}\.db$`)
	if got := s.BuildBackupFilename(BackupNameOptions{Date: true}, ""); !date.MatchString(got) {
		t.Errorf("date only = %q; want vpn-ui_<8 digits>.db", got)
	}
	dateTime := regexp.MustCompile(`^vpn-ui_\d{8}_\d{6}\.db$`)
	if got := s.BuildBackupFilename(BackupNameOptions{Date: true, Time: true}, ""); !dateTime.MatchString(got) {
		t.Errorf("date+time = %q; want vpn-ui_<date>_<time>.db", got)
	}
}

// The pre-update snapshot's name has to carry the clock, not just the version:
// naming it for the version alone is what made a second update from that version
// overwrite the only copy the operator had.
func TestBuildBackupFilenamePreUpdateIsMultiSlot(t *testing.T) {
	var s ServerService
	got := s.BuildBackupFilename(BackupNameOptions{Date: true, Time: true, Version: true}, "")

	version := sanitizeBackupNamePart(config.GetVersion())
	if version != "" && !strings.Contains(got, version) {
		t.Errorf("%q does not name the outgoing version %q", got, version)
	}
	if !regexp.MustCompile(`_\d{8}_\d{6}\.db$`).MatchString(got) {
		t.Errorf("%q carries no timestamp, so a second update from this version would overwrite it", got)
	}
	// The name is joined onto the backups/ directory, so it must stay inside it.
	if dir := filepath.Dir(filepath.Join("/opt/vpn-ui", got)); dir != "/opt/vpn-ui" {
		t.Errorf("%q escapes its directory (resolved to %q)", got, dir)
	}
}

func TestSanitizeBackupNamePart(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "panel1", "panel1"},
		// A space collapses to nothing, not to an underscore: the underscore is the
		// component SEPARATOR and injecting one would read as an extra component.
		{"spaces", "My Panel", "MyPanel"},
		{"version keeps dots", "1.8.9", "1.8.9"},
		{"domain keeps dots", "vpn.example.com", "vpn.example.com"},
		{"unicode drops out entirely", "پنل من", ""},
		{"path fragment", "..", ""},
		{"dot run", "...", ""},
		{"leading dot", ".hidden", "hidden"},
		{"separator survives", "my_panel", "my_panel"},
		{"ipv6 brackets", "[2001:db8::1]", "2001db81"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeBackupNamePart(tt.in); got != tt.want {
				t.Errorf("sanitizeBackupNamePart(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}

	long := strings.Repeat("a", backupNameComponentMax+40)
	if got := sanitizeBackupNamePart(long); len(got) != backupNameComponentMax {
		t.Errorf("a %d-char component was not capped: got %d chars", len(long), len(got))
	}
}

// Whatever the builder assembles has to survive /getDb's own filename check, or
// the download 400s instead of arriving.
func TestBuildBackupFilenamePassesTheFilenameGate(t *testing.T) {
	var s ServerService
	for _, opts := range []BackupNameOptions{
		{},
		{Date: true},
		{Date: true, Time: true},
		{Date: true, Time: true, Version: true},
	} {
		got := s.BuildBackupFilename(opts, "203.0.113.9:2083")
		if !filenameGate.MatchString(got) {
			t.Errorf("%+v produced %q, which /getDb would reject", opts, got)
		}
	}
}
