package service

import (
	"fmt"
	"os"
	"path/filepath"
)

// Whether the panel renews a certificate on its own.
//
// WHERE THE FLAG LIVES, and why not in the settings table. A profile is a
// directory, and everything else about it already lives in that directory: the
// active link, the version tree, the acme home, the ledger, the issuance lock. Two
// consequences make the filesystem the right home rather than a settings row:
//
//   - SSLProfileNames and sslInsideManagedStore are deliberately database-free
//     (sslprofile.go), because containment has to be answerable with no DB at all.
//     A flag in the settings table would be a second source of truth about a
//     profile that only half the code could read.
//   - DeleteSSLProfile is one os.RemoveAll of the store root. A settings row would
//     outlive the certificate it described, and the next certificate to reuse that
//     slug would silently inherit a stranger's preference.
//
// ABSENCE MEANS ON, which is the only safe default and the reason this is an "off"
// marker rather than an "on" one. Every install that existed before this file did
// renews unattended; a flag whose absence meant off would silently stop all of them
// on upgrade, and the failure would surface as an expired certificate weeks later.
//
// The marker sits beside the version tree, never inside a version, so a rollback
// cannot carry a stale preference back with it.

// sslAutoRenewOffFile is the marker whose PRESENCE turns unattended renewal off.
const sslAutoRenewOffFile = "autorenew.off"

// SSLAutoRenewEnabled reports whether the panel renews this profile on its own.
// Anything it cannot determine answers true, because failing safe here means
// renewing a certificate nobody asked it not to.
func SSLAutoRenewEnabled(profile string) bool {
	root, err := SSLProfileRoot(profile)
	if err != nil {
		return true
	}
	return sslAutoRenewEnabledAt(root)
}

func sslAutoRenewEnabledAt(root string) bool {
	if _, err := os.Stat(filepath.Join(root, sslAutoRenewOffFile)); err == nil {
		return false
	}
	// Absent, or a directory we cannot read. Either way renew: the alternative is
	// letting a permissions problem quietly stop renewing a live certificate.
	return true
}

// SetSSLAutoRenew turns unattended renewal on or off for one certificate.
//
// Writes nothing at all in the ON case beyond removing the marker, so a profile
// that never had the flag touched keeps an untouched directory.
func SetSSLAutoRenew(profile string, enabled bool) error {
	_, root, err := sslResolveProfile(profile)
	if err != nil {
		return err
	}
	marker := filepath.Join(root, sslAutoRenewOffFile)
	if enabled {
		if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("turning auto renew on: %w", err)
		}
		return nil
	}
	// The store root has to exist to hold a marker. It always does for a profile
	// with a certificate in it, which is the only kind the page can toggle.
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("turning auto renew off: %w", err)
	}
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("turning auto renew off: %w", err)
	}
	defer f.Close()
	// Written for whoever finds this file on disk months later, not for the code:
	// nothing reads the contents, only whether the file is there.
	_, _ = f.WriteString("The panel does not renew this certificate on its own.\n" +
		"Delete this file, or turn Auto renew back on in the panel, to resume unattended renewal.\n")
	return nil
}
