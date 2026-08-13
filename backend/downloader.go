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

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// DownloadBundlesIfMissing attempts to download prebuilt core and daemon bundles
// from this repository's GitHub release for the current version when embedded
// bundles are not present. It writes binaries into BinDir(). This is a best-effort
// fallback to reduce "no such file" startup failures on fresh checkouts.
func DownloadBundlesIfMissing() {
	ver := config.GetVersion()
	if ver == "" {
		logger.Info("no release version available; skipping bundle download")
		return
	}
	binDir := BinDir()
	_ = os.MkdirAll(binDir, 0o755)

	arch := runtime.GOARCH
	osName := runtime.GOOS

	// Try to fetch a core archive for this arch, or a flat xray binary.
	tryFiles := []string{
		fmt.Sprintf("core-%s.tgz", arch),
		fmt.Sprintf("core-%s.tar.gz", arch),
		fmt.Sprintf("xray-%s-%s", osName, arch),
		fmt.Sprintf("xray-%s", arch),
	}

	for _, f := range tryFiles {
		url := fmt.Sprintf("https://github.com/hasan1808/vpn-ui/releases/download/v%s/%s", ver, f)
		if tryDownloadFile(url, f, binDir) {
			logger.Info("downloaded and installed bundle file:", f)
			// If we downloaded an archive, extraction already placed files in binDir.
			// If we downloaded a flat xray binary, ensure it's executable.
			return
		}
	}

	// Try the backend bundle archives (daemons)
	tryBackends := []string{
		fmt.Sprintf("backend-%s.tgz", arch),
		fmt.Sprintf("backend-%s.tar.gz", arch),
		fmt.Sprintf("daemons-%s.tgz", arch),
	}
	for _, f := range tryBackends {
		url := fmt.Sprintf("https://github.com/hasan1808/vpn-ui/releases/download/v%s/%s", ver, f)
		if tryDownloadFile(url, f, binDir) {
			logger.Info("downloaded and installed backend bundle:", f)
			return
		}
	}

	// Fallback: try individual daemon names
	for _, d := range Daemons {
		candidates := []string{
			fmt.Sprintf("%s-%s-%s", d.Name, osName, arch),
			fmt.Sprintf("%s-%s", d.Name, arch),
			d.Name,
		}
		for _, c := range candidates {
			url := fmt.Sprintf("https://github.com/hasan1808/vpn-ui/releases/download/v%s/%s", ver, c)
			if tryDownloadFile(url, c, binDir) {
				logger.Infof("downloaded daemon %s", c)
				break
			}
		}
	}
}

// tryDownloadFile downloads url and writes it into binDir with name `destName`.
// If the file looks like a tar.gz (.tgz/.tar.gz) it extracts its contents into binDir.
// Returns true on success (HTTP 200 and file written/extracted).
func tryDownloadFile(url, destName, binDir string) bool {
	logger.Debug("attempting download:", url)
	resp, err := http.Get(url)
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
