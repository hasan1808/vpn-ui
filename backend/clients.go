package backend

import (
	"os"
	"path/filepath"
)

// The bundled VPN CLIENTS. Everything else in this package exists so the panel
// can SERVE a protocol; these exist so it can dial out as somebody else's
// client, which for three protocols needs a different upstream project
// entirely: pptpd, ocserv and accel-ppp are server-only, so PPTP, OpenConnect
// and SSTP outbounds are pptp (pptpclient), openconnect and sstpc respectively.
//
// They are flat binaries in the same //go:embed all:bin as the daemons, not
// relocatable trees, because none of them dlopens anything. The two non-obvious
// members are the ones that are not the client binary itself: vpnc-script, which
// openconnect delegates all routing to, and sstp-pppd-plugin.so, which pppd (not
// sstpc) loads.
//
// Extraction is separate from the core catalog on purpose. "Installed" for a
// core is decided by its daemon being on disk, so a client binary must never be
// laid down by a core's install; conversely an outbound has to work on a host
// that serves no VPN at all, so it cannot wait for one. ExtractClients is that
// second trigger.
const (
	PptpClient        = "pptp"
	OpenconnectClient = "openconnect"
	SstpClient        = "sstpc"

	// VpncScript is openconnect's routing/DNS/MTU hook, a POSIX script that
	// drives iproute2 rather than an ELF.
	VpncScript = "vpnc-script"

	// SstpPppdPlugin passes pppd's MPPE keys to sstpc so it can compute the
	// SSTP crypto binding. pppd resolves a `plugin` argument containing a
	// slash by dlopen'ing it directly, so it is loaded by absolute path and
	// does not have to live in pppd's compiled-in plugin dir.
	SstpPppdPlugin = "sstp-pppd-plugin.so"

	// VpncScriptLink is the path openconnect was compiled to look for
	// vpnc-script at (--with-vpnc-script). The extracted copy lives next to
	// the panel binary, which moves with the install location, so LinkVpncScript
	// points this fixed sentinel at it. Same arrangement as PptpCtrlLink.
	VpncScriptLink = PppdBundleRoot + "/vpnc-script"
)

// ClientNames returns the file names of every bundled client-side artifact.
func ClientNames() []string {
	var out []string
	for _, d := range Daemons {
		if d.Client {
			out = append(out, d.Name)
		}
	}
	return out
}

// clientCompanions maps a client binary to the artifacts it is useless without.
// Both entries are the same shape of bug: the binary is there, the run gets far
// enough to look like it is working, and then it fails somewhere that names
// nothing. So availability is answered for the whole set, never for the ELF
// alone.
var clientCompanions = map[string][]string{
	OpenconnectClient: {VpncScript},
	SstpClient:        {SstpPppdPlugin},
}

// ExtractClients writes the client-side binaries into BinDir. Unlike the
// per-core daemon extraction it takes no selection: the set is small (about
// 9 MB), it is shared across protocols (sstpc and openconnect both dial through
// the same panel plumbing), and no core's "installed" state is derived from any
// of these files, so there is nothing to keep off disk. Idempotent, and a no-op
// when this build embeds no bundle.
//
// CONTRACT, because it is not obvious from the panel: NOTHING calls this today.
// Setup extracts per core, and no core owns a client, so on a current install
// these files never reach disk on their own. An outbound driver must call
// EnsureClients itself before it execs anything.
func ExtractClients() ([]string, error) {
	written, err := ExtractOnly(ClientNames())
	if err != nil {
		return written, err
	}
	// Best effort: openconnect still runs with a missing sentinel as long as the
	// caller passes --script, so a read-only /usr must not fail the extraction.
	_ = LinkVpncScript()
	return written, nil
}

// EnsureClients lays the client artifacts down if they are not already there,
// and is the call an outbound driver makes before raising a tunnel. Safe to call
// on every raise: it costs one stat per artifact once they exist, and the write
// itself replaces a file through a rename, so it cannot disturb a client process
// that is already running from the old inode.
//
// It is deliberately NOT called from ClientAvailable. Availability is asked at
// save time, possibly for a config the operator is only drafting, and a
// predicate that writes 9 MB to disk as a side effect of being asked a question
// is a trap for whoever calls it next.
func EnsureClients() error {
	// sstpc first, and unconditionally: it is a TREE rather than a file in BinDir,
	// so HasClients below cannot see it and ExtractClients would not lay it down.
	// Cheap when it is already there (the untar overwrites identical files).
	if !SstpcBundleReady() {
		if err := ExtractSstpcBundle(); err != nil {
			return err
		}
	}
	if HasClients() {
		// The link is cheap and self-correcting, and it is the one piece of state
		// that can go stale on its own (the panel binary moving relocates BinDir).
		_ = LinkVpncScript()
		return nil
	}
	_, err := ExtractClients()
	return err
}

// ClientPath returns the extracted path of a bundled client artifact, or "" when
// it is absent. A thin alias for DaemonPath that reads correctly at the call
// site, where "daemon" would be the wrong word for a dial-out helper.
//
// sstpc is the one that is not in BinDir at all: it unpacks as a tree, so its
// launcher is resolved from the bundle root instead.
func ClientPath(name string) string {
	if name == SstpClient {
		return SstpcPath()
	}
	return DaemonPath(name)
}

// HasClients reports whether the client binaries have been extracted. Both
// halves of the SSTP pair are required: sstpc without the plugin connects,
// authenticates, and is then dropped by any server that checks the crypto
// binding, which is the harder failure to read from a log.
func HasClients() bool {
	for _, n := range ClientNames() {
		if ClientPath(n) == "" {
			return false
		}
	}
	return true
}

// ClientAvailable answers whether an outbound of this kind can run on this host,
// and when it cannot, one line an operator can act on. It is the query behind an
// outbound driver's Available(), so it is asked at SAVE time, about a config
// that may never be raised: it only looks, it never extracts.
//
// "Available" means the artifacts are on disk OR embedded in this build, because
// EnsureClients turns the second into the first at raise time. Refusing a save
// for a client that is one extraction away would reject a perfectly good config.
// What it does refuse is the case that no amount of retrying fixes: a panel
// built without the daemon bundle, or built for an architecture the bundle does
// not cover, where the file is simply not in the binary.
//
// Pass the client name (PptpClient, OpenconnectClient, SstpClient). The
// companions are checked too, and the reason names whichever artifact is
// actually missing, so "openconnect works but its vpnc-script does not" reads as
// itself rather than as a generic openconnect failure.
func ClientAvailable(name string) (bool, string) {
	if !isClient(name) {
		return false, name + " is not a bundled client"
	}
	for _, n := range append([]string{name}, clientCompanions[name]...) {
		if ok, reason := artifactAvailable(n); !ok {
			return false, reason
		}
	}
	return true, ""
}

// artifactAvailable is ClientAvailable for a single file.
func artifactAvailable(name string) (bool, string) {
	// The tree, not a file in BinDir. Embedded is enough: EnsureClients extracts it
	// on the way to the first dial, exactly as it does for the flat artifacts.
	if name == SstpClient {
		if SstpcPath() != "" || HasSstpcBundle() {
			return true, ""
		}
		return false, clientMissingReason(name)
	}
	p := filepath.Join(BinDir(), name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		// A present but non-executable artifact is its own failure, not a missing
		// one: it means an extraction was interrupted or something re-wrote the
		// file, and saying "not included in this build" there would send the
		// operator looking in the wrong place entirely.
		if st.Mode().Perm()&0o111 == 0 {
			return false, clientLabel(name) + " at " + p + " is not executable, so the bundle extraction did not finish"
		}
		return true, ""
	}
	if isEmbedded(name) {
		return true, "" // EnsureClients will write it on first use
	}
	return false, clientMissingReason(name)
}

// isClient reports whether name is a client artifact in the manifest.
//
// SstpClient is accepted explicitly: it left the flat manifest when it became a
// relocatable tree, and without this every SSTP save would be refused with
// "sstpc is not a bundled client".
func isClient(name string) bool {
	if name == SstpClient {
		return true
	}
	for _, d := range Daemons {
		if d.Name == name && d.Client {
			return true
		}
	}
	return false
}

// isEmbedded reports whether this build carries the named artifact for this
// architecture, whether or not it has been extracted.
func isEmbedded(name string) bool {
	f, err := bundleFS.Open(archDir() + "/" + name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// clientLabel names an artifact the way an operator would recognise it. The two
// companions are named through the client they serve, because on their own the
// file names mean nothing to whoever is reading the error.
func clientLabel(name string) string {
	switch name {
	case VpncScript:
		return "openconnect's vpnc-script helper"
	case SstpPppdPlugin:
		return "sstpc's " + SstpPppdPlugin + " pppd plugin"
	default:
		return "the " + name + " client"
	}
}

// clientMissingReason explains an artifact that is not in this build at all,
// including what breaks without it: a missing companion is invisible at raise
// time, so the consequence is the useful half of the message.
func clientMissingReason(name string) string {
	switch name {
	case VpncScript:
		return clientLabel(name) + " was not included in this build, so the tunnel would come up carrying no routes"
	case SstpPppdPlugin:
		return clientLabel(name) + " was not included in this build, so the SSTP crypto binding cannot be answered and the server drops the call after login"
	default:
		return clientLabel(name) + " was not included in this build: the daemon bundle was built without it, or not for this architecture"
	}
}

// VpncScriptPath is the extracted vpnc-script, to be passed to openconnect as
// --script. Prefer this over relying on the compiled-in default: the default is
// a symlink LinkVpncScript maintains, and /usr may be read-only.
func VpncScriptPath() string { return ClientPath(VpncScript) }

// SstpPluginPath is the extracted sstp-pppd-plugin.so, to be passed to pppd as
// `plugin <path>`. Empty when the bundle is absent, in which case SSTP dial-out
// must not be attempted: the handshake would fail at the crypto binding rather
// than at anything that names the missing plugin.
func SstpPluginPath() string { return ClientPath(SstpPppdPlugin) }

// LinkVpncScript points openconnect's compiled-in vpnc-script path at the
// extracted copy, so the binary works even when a caller omits --script. No-op
// when the script is not extracted. Idempotent; mirrors LinkPptpCtrl.
func LinkVpncScript() error {
	script := ClientPath(VpncScript)
	if script == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(VpncScriptLink), 0o755); err != nil {
		return err
	}
	// Remove, not overwrite: this is also how a stale link from a previous
	// install location gets corrected.
	_ = os.Remove(VpncScriptLink)
	return os.Symlink(script, VpncScriptLink)
}
