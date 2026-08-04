package backend

import "os"

// The sstpc relocatable bundle backs the SSTP OUTBOUND (dialling somebody else's
// SSTP server; accel-ppp serves SSTP and has no client mode at all).
//
// It is a tree rather than the flat binary the other two clients are, and for a
// reason that is not about dlopen'ing plugins the way charon and accel-ppp are:
// sstpc needs MD4, which OpenSSL 3 keeps in the `legacy` PROVIDER, a module loaded
// with dlopen. sstpc hashes the account password to the NT hash and derives the MPPE
// keys itself, to answer the crypto binding the SSTP server challenges it with right
// after a successful PPP login. A fully static musl binary cannot dlopen anything, so
// the static sstpc this used to ship failed on EVERY host, before any socket, with
// "Could not load legacy crypto provider" -> "Could not initialize the client".
//
// So it ships as pppd/accel-ppp/strongSwan do: a musl tree whose entry point
// sbin/sstpc is a loader-wrapper launcher (works on any host libc) that also exports
// OPENSSL_MODULES so lib/ossl-modules/legacy.so is found. The fixed root here MUST
// equal the PREFIX in build/backend/sstpc-bundle.sh.
//
// The pppd PLUGIN that goes with it stays a FLAT file (SstpPppdPlugin, in the Daemons
// manifest): pppd loads it, not sstpc, by an absolute path this panel passes on the
// command line, and it is linked to carry no dependency of its own.
const (
	// SstpcBundleRoot is where the tree unpacks; its own subdir under the shared
	// /usr/libexec prefix so it never collides with the other bundles.
	SstpcBundleRoot = "/usr/libexec/vpn-ui-sstpc" // must equal the bundle build PREFIX

	// SstpcBundled is the launcher the SSTP outbound driver hands to pppd as its
	// `pty` command.
	SstpcBundled = SstpcBundleRoot + "/sbin/sstpc"
)

func sstpcBundleName() string { return archDir() + "/sstpc-bundle.tgz" }

// HasSstpcBundle reports whether an sstpc bundle is embedded for this architecture.
func HasSstpcBundle() bool {
	f, err := bundleFS.Open(sstpcBundleName())
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// SstpcBundleReady reports whether the bundle is embedded AND already extracted.
func SstpcBundleReady() bool {
	if !HasSstpcBundle() {
		return false
	}
	st, err := os.Stat(SstpcBundled)
	return err == nil && !st.IsDir()
}

// ExtractSstpcBundle untars the embedded bundle to the filesystem root (its entries
// are rooted at usr/libexec/vpn-ui-sstpc). Idempotent; no-op if the bundle is absent.
func ExtractSstpcBundle() error {
	if !HasSstpcBundle() {
		return nil
	}
	return extractBundleTGZ(sstpcBundleName())
}

// SstpcPath returns the extracted launcher, or "" when it is not bundled or not yet
// on disk. The SSTP driver calls EnsureClients first, which extracts it.
func SstpcPath() string {
	if !HasSstpcBundle() {
		return ""
	}
	if st, err := os.Stat(SstpcBundled); err == nil && !st.IsDir() {
		return SstpcBundled
	}
	return ""
}
