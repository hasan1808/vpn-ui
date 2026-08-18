package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/logger"
)

// assetFingerprint hashes the embedded asset tree and returns the release version
// with a short digest appended, e.g. "1.8.9-4f2c1ab903".
//
// This is what every `assets/...?{{ .asset_ver }}` carries. The digest covers each
// file's path and its bytes, so it moves when and only when the served assets move:
// two builds of the same release with a one-line css change get different tokens,
// and rebuilding without touching assets keeps the browser's cached copies valid.
//
// Walking 98 files / ~9MB costs a few tens of milliseconds, paid once at server
// start, which buys the guarantee that html and javascript from different builds
// can never meet in one page.
func assetFingerprint() string {
	h := sha256.New()
	err := fs.WalkDir(assetsFS, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		// The path goes in as well as the content: renaming a file changes what a
		// page loads even when no byte of any file changed.
		h.Write([]byte(path))
		f, err := assetsFS.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(h, f)
		return err
	})
	if err != nil {
		// A token that cannot be trusted to change is worse than none, so fall back to
		// the release version and say so: the panel still serves, and the operator has
		// the one line that explains a stale asset if they ever hit one.
		logger.Warning("could not fingerprint embedded assets, falling back to the release version for asset URLs:", err)
		return config.GetVersion()
	}
	return config.GetVersion() + "-" + hex.EncodeToString(h.Sum(nil))[:10]
}
