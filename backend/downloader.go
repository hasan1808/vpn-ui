package backend

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/corebundle"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// bundleDownloadTimeout bounds every network request this downloader makes.
// Startup runs this function BEFORE the web server is up, so an unbounded
// http.Get (the old code) could freeze the panel forever on a stalled or
// throttled connection to GitHub — exactly what a bare `http.Get` has no
// answer for.
const bundleDownloadTimeout = 45 * time.Second

// xrayOnDisk reports whether the panel's expected Xray binary already exists in
// BinDir. The release pipeline does NOT embed the core: build/core/build.sh runs
// after the go build and ships core-<arch>.tgz as a separate release asset, so
// the first start downloads it once and extraction drops the binary here. That
// file being present is therefore the "core already satisfied" signal.
func xrayOnDisk() bool {
	binDir := BinDir()
	for _, n := range []string{"xray-" + runtime.GOOS + "-" + runtime.GOARCH, "xray"} {
		if fi, err := os.Stat(filepath.Join(binDir, n)); err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

// daemonsOnDisk reports whether at least one bundled daemon has already been
// extracted to BinDir (from the embedded bundle or a previous backend download).
// Mirrors xrayOnDisk so a checkout build that fetched backend-<arch>.tgz once
// stops re-downloading it on every start.
func daemonsOnDisk() bool {
	binDir := BinDir()
	for _, d := range Daemons {
		if fi, err := os.Stat(filepath.Join(binDir, d.Name)); err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

// DownloadBundlesIfMissing attempts to download prebuilt core and daemon bundles
// from this repository's GitHub release for the current version when the assets
// are not already present. It writes binaries into BinDir(). This is a best-effort
// fallback to reduce "no such file" startup failures on fresh checkouts.
//
// The release binary embeds the daemon bundle, while the core ships as a separate
// release asset that the first start downloads once. Either way, once everything
// needed is on disk (embedded or extracted) the fast path below is a pure no-op
// and startup never touches the network. The old code re-ran the downloader on
// EVERY start with a bare http.Get (no timeout), so a stalled github.com link
// parked the panel before its web server ever came up — the "panel stopped,
// unit active" state after an update.
func DownloadBundlesIfMissing() {
	ver := config.GetVersion()
	if ver == "" {
		logger.Info("no release version available; skipping bundle download")
		return
	}
	haveCore := corebundle.HasXray() || xrayOnDisk()
	haveDaemons := Available() || daemonsOnDisk()
	if haveCore && haveDaemons {
		return
	}
	client := &http.Client{Timeout: bundleDownloadTimeout}
	binDir := BinDir()
	_ = os.MkdirAll(binDir, 0o755)

	arch := runtime.GOARCH
	osName := runtime.GOOS

	// Try to fetch a core archive for this arch, or a flat xray binary.
	if !haveCore {
		tryFiles := []string{
			fmt.Sprintf("core-%s.tgz", arch),
			fmt.Sprintf("core-%s.tar.gz", arch),
			fmt.Sprintf("xray-%s-%s", osName, arch),
			fmt.Sprintf("xray-%s", arch),
		}

		for _, f := range tryFiles {
			url := fmt.Sprintf("https://github.com/hasan1808/vpn-ui/releases/download/v%s/%s", ver, f)
			if tryDownloadFile(client, url, f, binDir) {
				logger.Info("downloaded and installed bundle file:", f)
				// If we downloaded an archive, extraction already placed files in binDir.
				// If we downloaded a flat xray binary, ensure it's executable.
				if haveDaemons {
					return
				}
				haveCore = true
				break
			}
		}
	}

	// Try the backend bundle archives (daemons)
	if !haveDaemons {
		tryBackends := []string{
			fmt.Sprintf("backend-%s.tgz", arch),
			fmt.Sprintf("backend-%s.tar.gz", arch),
			fmt.Sprintf("daemons-%s.tgz", arch),
		}
		for _, f := range tryBackends {
			url := fmt.Sprintf("https://github.com/hasan1808/vpn-ui/releases/download/v%s/%s", ver, f)
			if tryDownloadFile(client, url, f, binDir) {
				logger.Info("downloaded and installed backend bundle:", f)
				return
			}
		}
	}

	// Fallback: try individual daemon names
	if !haveDaemons {
		for _, d := range Daemons {
			candidates := []string{
				fmt.Sprintf("%s-%s-%s", d.Name, osName, arch),
				fmt.Sprintf("%s-%s", d.Name, arch),
				d.Name,
			}
			for _, c := range candidates {
				url := fmt.Sprintf("https://github.com/hasan1808/vpn-ui/releases/download/v%s/%s", ver, c)
				if tryDownloadFile(client, url, c, binDir) {
					logger.Infof("downloaded daemon %s", c)
					break
				}
			}
		}
	}
}

// tryDownloadFile downloads url and writes it into binDir with name `destName`.
// If the file looks like a tar.gz (.tgz/.tar.gz) it extracts its contents into binDir.
// Returns true on success (HTTP 200 and file written/extracted).
func tryDownloadFile(client *http.Client, url, destName, binDir string) bool {
	logger.Debug("attempting download:", url)
	resp, err := client.Get(url)
	if err != nil {
		logger.Debug("download failed:", err)
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Debugf("download %s returned status %d", url, resp.StatusCode)
		return false
	}
	// If archive
	if strings.HasSuffix(destName, ".tgz") || strings.HasSuffix(destName, ".tar.gz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			logger.Debug("gzip reader failed:", err)
			return false
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				logger.Debug("tar read failed:", err)
				return false
			}
			if hdr.Typeflag != tar.TypeReg {
				continue
			}
			base := filepath.Base(hdr.Name)
			tgt := filepath.Join(binDir, base)
			f, err := os.Create(tgt)
			if err != nil {
				logger.Debug("create file failed:", err)
				return false
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				logger.Debug("write file failed:", err)
				return false
			}
			f.Close()
			_ = os.Chmod(tgt, 0o755)
			// Special-case: if the archive contained a plain "xray" binary, also
			// write the architecture-specific name the panel expects (xray-<os>-<arch>),
			// since some archives produce a flat "xray" while the code looks for
			// xray-<os>-<arch> first.
			if base == "xray" {
				archName := fmt.Sprintf("xray-%s-%s", runtime.GOOS, runtime.GOARCH)
				alt := filepath.Join(binDir, archName)
				// Copy the file to the alt name.
				if data, err := os.ReadFile(tgt); err == nil {
					_ = os.WriteFile(alt, data, 0o755)
				}
			}
		}
		return true
	}

	// Otherwise write as a flat file
	outPath := filepath.Join(binDir, filepath.Base(destName))
	f, err := os.Create(outPath)
	if err != nil {
		logger.Debug("create file failed:", err)
		return false
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		logger.Debug("write file failed:", err)
		return false
	}
	_ = os.Chmod(outPath, 0o755)
	return true
}
