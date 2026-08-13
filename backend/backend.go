// Package backend bundles the VPN daemon binaries (xl2tpd, and later
// openvpn/libreswan/pppd) directly into the vpn-ui executable via go:embed and
// extracts them at runtime. This lets the panel "bake in" the backend instead
// of installing daemons per-distro through the host package manager.
//
// The bundled binaries are built statically against musl (see
// build/backend/build.sh) so they run on any Linux distribution regardless of
// its libc — including minimal cloud images. Kernel modules are still a host
// concern (they can't be bundled); those are handled by the provisioning step.
package backend

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"embed"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/config"
)

// bundleFS holds the per-architecture daemon binaries. The `all:` prefix keeps
// the embed working when only the .gitkeep placeholder is present (a checkout
// without the prebuilt binaries still compiles — Extract simply becomes a no-op).
//
//go:embed all:bin
var bundleFS embed.FS

// Daemon describes one bundled daemon.
type Daemon struct {
	Name string // binary file name, e.g. "xl2tpd"

	// Client marks a binary the panel dials OUT with instead of a server it
	// listens with. The flag exists because the two have different install
	// triggers: a server binary lands when its core is installed, while an
	// outbound can be configured on a host that serves nothing at all, so the
	// clients belong to no catalog row and are extracted on their own
	// (see clients.go). One manifest, so the two lists cannot drift apart.
	Client bool
}

// Daemons is the manifest of bundled daemons (extended as more are added).
var Daemons = []Daemon{
	{Name: "xl2tpd"},
	{Name: "xl2tpd-control"},
	{Name: "openvpn"},
	{Name: "pptpd"},
	{Name: "pptpctrl"},
	{Name: "ocserv"},
	{Name: "ocserv-worker"},
	{Name: "occtl"},
	// telemt (MTProto Proxy) is a single fully-static musl binary with no plugins to
	// dlopen and no fixed install path, so it belongs in this flat manifest rather
	// than needing a relocatable tree bundle like accel-ppp/strongSwan.
	{Name: "telemt"},

	// The client side. Three protocols the panel can serve can also be dialed
	// out to, but only by separate upstream projects: pptpd, ocserv and
	// accel-ppp are all server-only, so none of the binaries above can be
	// pointed at a remote gateway. Each of these is fully static for the same
	// reason telemt is (nothing here dlopens anything), with the one exception
	// noted at the plugin.
	{Name: "pptp", Client: true},
	{Name: "openconnect", Client: true},
	// Not an ELF. openconnect brings a tunnel up and then delegates every
	// route, DNS and MTU change to this script, so a session without it
	// authenticates and then carries no traffic: as required as the binary.
	// Extract makes it 0755 like every other entry.
	{Name: "vpnc-script", Client: true},
	// sstpc is NOT here. It is the one client that cannot be a flat static binary:
	// it needs MD4 out of OpenSSL 3's `legacy` provider, which is dlopen'd, and a
	// fully static musl build cannot dlopen at all. It ships as a relocatable tree
	// instead (backend/sstpc.go, SstpcBundleRoot), like pppd and strongSwan.
	// The exception: PPPD loads this, not sstpc. It is how pppd's MPPE keys
	// reach sstpc, which needs them to answer the SSTP crypto binding that
	// Windows RRAS and accel-ppp both verify. Being musl-linked, only the
	// BUNDLED pppd can dlopen it, so the dial path must invoke PppdBundled by
	// path rather than deferring to a host pppd the way UsingBundledPppd does.
	{Name: "sstp-pppd-plugin.so", Client: true},
}

// PptpCtrlLink is the fixed path pptpd was compiled to exec pptpctrl from
// (--sbindir sentinel). Provisioning symlinks it to the extracted pptpctrl so
// the bundle works regardless of where vpn-ui is installed.
const PptpCtrlLink = "/usr/libexec/vpn-ui/pptpctrl"

// archDir is the embedded sub-directory for the running architecture.
func archDir() string { return "bin/" + runtime.GOARCH }

// Available reports whether a daemon bundle is embedded for this architecture.
func Available() bool {
	entries, err := bundleFS.ReadDir(archDir())
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	return false
}

// BinDir is the absolute directory where daemons are extracted. It is the SAME
// "bin" folder the Xray core uses (config.GetBinFolderPath()), so every backend
// file lands flat in bin/ with no sub-folder — resolved next to the vpn-ui
// executable, so it adapts to any install location (/usr/local/vpn-ui,
// /usr/lib/vpn-ui, …). An absolute VPNUI_BIN_FOLDER is honored as-is.
func BinDir() string {
	bin := config.GetBinFolderPath()
	if filepath.IsAbs(bin) {
		return bin
	}

	// Candidate directories (in order of preference) where the bin/ folder might live.
	// 1) next to the running executable (usual install: /usr/local/vpn-ui/bin)
	// 2) sibling of the executable when the executable is placed in a system 'bin'
	//    directory (e.g. /usr/local/bin -> /usr/local/vpn-ui/bin)
	// 3) a distro/libexec location used by some bundles
	// 4) fallback: next to the executable
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("/usr/local/vpn-ui", bin)
	}
	exeDir := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(exeDir, bin),                                 // ./bin next to exe
		filepath.Join(filepath.Dir(exeDir), "vpn-ui", bin),       // sibling /usr/local/vpn-ui/bin
		filepath.Join("/usr/local/vpn-ui", bin),                  // legacy
		filepath.Join("/usr/libexec/vpn-ui", "bin"),            // alternate
	}
	// Return the first candidate that already exists; otherwise return the first
	// candidate so callers can create it.
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return candidates[0]
}

// DaemonPath returns the extracted path of a bundled daemon if it exists on
// disk, otherwise "".
func DaemonPath(name string) string {
	p := filepath.Join(BinDir(), name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

// Bundled reports whether the named daemon binary is EMBEDDED for the running
// architecture, regardless of whether it has been extracted to disk yet.
//
// DaemonPath answers "is it installed right now"; Bundled answers "can this
// host ever install it". The two must not be conflated: a fresh host has
// extracted nothing, so DaemonPath alone would make every not-yet-installed
// daemon read as "not bundled for this architecture" (see mtprotoStatus).
func Bundled(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\") {
		return false
	}
	if strings.HasSuffix(name, ".tgz") {
		return false // archive bundles extract as trees, not flat BinDir binaries
	}
	_, err := bundleFS.ReadFile(archDir() + "/" + name)
	return err == nil
}

// Extract writes all bundled daemon binaries for this architecture into BinDir()
// with 0755 permissions. It is idempotent (overwrites existing files) and a
// no-op when no bundle is embedded. Returns the list of files written.
func Extract() ([]string, error) { return extract(nil) }

// ExtractOnly writes just the named bundled daemons. Names are binary file names
// as listed in Daemons, e.g. "xl2tpd". A name with no matching embedded file is
// skipped silently: bundles are per-architecture, so asking for a daemon this
// build does not ship is a normal outcome, not an error.
//
// An EMPTY list extracts nothing, which is the only safe reading of "extract
// only these". It deliberately does NOT mean "everything" (use Extract for
// that): the cores with no daemon of their own (SSTP, IKEv2, WireGuard,
// AmneziaWG) ask for an empty set on every install, and an empty-means-all
// contract silently laid down the entire bundle for them, which is exactly the
// thing per-core setup exists to prevent.
//
// The selective form exists because "installed" is decided by the binary being
// on disk (DaemonPath / daemonInstalled), so extracting everything would make
// every core report itself installed no matter which ones the operator picked.
func ExtractOnly(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	return extract(names)
}

// extract writes the bundled daemons for this architecture into BinDir with 0755
// permissions. A nil `names` means every daemon in the bundle. It is idempotent
// (overwrites existing files) and a no-op when no bundle is embedded.
func extract(names []string) ([]string, error) {
	if !Available() {
		return nil, nil
	}
	var want map[string]bool
	if names != nil {
		want = make(map[string]bool, len(names))
		for _, n := range names {
			want[n] = true
		}
	}
	dir := BinDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	entries, err := bundleFS.ReadDir(archDir())
	if err != nil {
		return nil, err
	}
	var written []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Archive bundles (e.g. the pppd tree) are extracted separately, not
		// dropped as a flat file into BinDir.
		if strings.HasSuffix(e.Name(), ".tgz") {
			continue
		}
		if want != nil && !want[e.Name()] {
			continue
		}
		data, err := bundleFS.ReadFile(archDir() + "/" + e.Name())
		if err != nil {
			return written, err
		}
		dest := filepath.Join(dir, e.Name())
		if err := writeExecutable(dest, data); err != nil {
			return written, err
		}
		written = append(written, dest)
	}
	return written, nil
}

// RemoveDaemons deletes the named extracted daemon binaries from BinDir. It is
// the inverse of ExtractOnly, used when a core is uninstalled; an absent file
// is not an error. Returns the paths actually removed.
func RemoveDaemons(names []string) ([]string, error) {
	dir := BinDir()
	var removed []string
	var firstErr error
	for _, n := range names {
		if n == "" || strings.ContainsAny(n, "/\\") {
			continue // only ever flat names inside BinDir
		}
		p := filepath.Join(dir, n)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if err := os.Remove(p); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		removed = append(removed, p)
	}
	return removed, firstErr
}

// writeExecutable writes an executable to dest via a temp file + atomic rename.
// A plain overwrite of a daemon that's currently running fails with ETXTBSY
// ("text file busy") because the kernel keeps the running binary's file mapped.
// Rename swaps the directory entry to a fresh inode instead — the running
// process keeps executing the old inode, and the next start picks up the new one.
func writeExecutable(dest string, data []byte) error {
	return WriteFileAtomic(dest, data, 0o755)
}

// WriteFileAtomic writes data to dest via a temp file + atomic rename, the same
// way writeExecutable does, but for any mode: bundle trees carry 0755 binaries
// next to 0644 configs and dictionaries.
//
// Every file a live daemon holds must be replaced this way, not just the ELF the
// wrapper names. A bundle's entry point execs the musl loader (lib/ld-musl-*.so.1)
// with the real binary as an argument, so the loader is what the kernel marks
// busy, so overwriting it in place is what raises ETXTBSY on a setup re-run. The
// .so and .bin files are worse: the kernel permits overwriting those under a live
// daemon, silently corrupting its mmap'd pages until it segfaults. Rename avoids
// both: the running process keeps the old inode and the next start gets the new one.
func WriteFileAtomic(dest string, data []byte, mode os.FileMode) error {
	tmp := dest + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		// O_CREATE|O_TRUNC happens before the write, so a failure part-way through
		// (ENOSPC, EIO, RLIMIT_FSIZE) leaves a partial file behind.
		_ = os.Remove(tmp)
		return err
	}
	// os.WriteFile applies the umask on create, so set the mode explicitly.
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// extractBundleTGZ untars an embedded relocatable bundle to the filesystem root. Its
// entries are stored at their real deploy path (usr/libexec/vpn-ui-<x>/...), so
// untarring at / recreates the tree exactly where the launchers expect it.
//
// New code only. ExtractPppdBundle, ExtractLibreswanBundle, ExtractAccelBundle and
// ExtractStrongswanBundle each carry an identical copy of this loop, written before
// there were four of them; they are deliberately left alone here rather than
// refactored underneath four working extraction paths at once.
func extractBundleTGZ(name string) error {
	data, err := bundleFS.ReadFile(name)
	if err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join("/", filepath.Clean("/"+hdr.Name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			_ = os.MkdirAll(filepath.Dir(target), 0o755)
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := extractRegularFile(target, tr, os.FileMode(hdr.Mode)&0o777); err != nil {
				return err
			}
		}
	}
}

// extractRegularFile writes one tar entry to target, atomically.
func extractRegularFile(target string, tr io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return err
	}
	return WriteFileAtomic(target, data, mode)
}
