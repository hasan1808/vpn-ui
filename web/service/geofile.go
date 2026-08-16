package service

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/corebundle"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"
)

// geofileEntry is one downloadable geo data file: where it comes from upstream,
// the name it takes on disk under bin/, and the size below which a response is
// not credible as that file.
type geofileEntry struct {
	URL      string
	FileName string
	MinBytes int64
}

// builtinGeofiles are the geo data files the panel knows how to fetch by itself.
// It is the complete set the routing editor can name, and mirrors the list
// build/core/build.sh embeds (keep the two in sync).
//
// All six are baked into the binary by default (see the corebundle package), so
// on a normal build these downloads are for refreshing stale data and for
// repairing a bin/ that lost a file. A GEO_LEAN=1 build ships only the base
// pair, and then EnsureGeofiles is what puts a country file on disk the first
// time a routing rule names one.
//
// MinBytes is a floor, not a measurement: the smallest of these is ~7MB, so
// anything under a megabyte is a rate-limit page or an error body, not geo data.
var builtinGeofiles = map[string]geofileEntry{
	"geoip.dat":      {"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat", "geoip.dat", 1 << 20},
	"geosite.dat":    {"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat", "geosite.dat", 1 << 20},
	"geoip_IR.dat":   {"https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat", "geoip_IR.dat", 1 << 20},
	"geosite_IR.dat": {"https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat", "geosite_IR.dat", 1 << 20},
	"geoip_RU.dat":   {"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat", "geoip_RU.dat", 1 << 20},
	"geosite_RU.dat": {"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat", "geosite_RU.dat", 1 << 20},
}

// builtinGeofileOrder is the display order for the dashboard's Geofiles list:
// the base pair first, then each country pair.
var builtinGeofileOrder = []string{
	"geosite.dat", "geoip.dat",
	"geosite_IR.dat", "geoip_IR.dat",
	"geosite_RU.dat", "geoip_RU.dat",
}

// fallbackAssetDirs are the directories the core probes after its own asset dir
// (common/platform/others.go GetAssetLocation). A file sitting in one of these,
// from a distro package or an older manual install, makes the config work, so a
// presence check that only looked at bin/ would reject a config that runs.
var fallbackAssetDirs = []string{
	"/usr/local/share/xray",
	"/usr/share/xray",
	"/opt/share/xray",
}

// geofileNamePattern is the shape the panel is willing to manage: a bare
// basename ending in .dat. It is what keeps a config-supplied reference from
// naming a path outside the asset dir.
var geofileNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+\.dat$`)

const (
	// geofileStallTimeout aborts a transfer that has stopped delivering bytes.
	// Bounds "stuck forever" without punishing a slow but progressing download.
	geofileStallTimeout = 60 * time.Second
	// geofileAutoMaxTime caps a download started off the automatic path, which
	// runs inside the Xray restart lock. Holding that lock buys nothing once the
	// core cannot start anyway, and releasing it keeps panel shutdown, self-update
	// and the once-a-second health job from piling up behind a slow transfer.
	geofileAutoMaxTime = 5 * time.Minute
	// geofileManualMaxTime caps a download an operator asked for, which blocks an
	// HTTP handler. Generous: geosite_RU.dat is ~74MB.
	geofileManualMaxTime = 30 * time.Minute
)

// geofileHTTPClient downloads geo data. It deliberately sets no overall Timeout:
// the per-transfer bound is applied per call (a stall guard plus a caller-chosen
// ceiling), because the right ceiling differs between the restart path and the
// Geofiles button. Bound the phases that can hang here.
var geofileHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	},
}

// isSafeGeofileName reports whether name is a bare .dat basename, with no path
// separators, no traversal and no absolute path.
func isSafeGeofileName(name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	if filepath.IsAbs(name) {
		return false
	}
	return geofileNamePattern.MatchString(name)
}

// minBytesFor is the size floor a file must clear to count as real geo data.
// Known files get their own floor; anything else only has to be non-trivial,
// since a custom alias may legitimately point at a small hand-built .dat.
func minBytesFor(name string) int64 {
	if entry, ok := builtinGeofiles[name]; ok && entry.MinBytes > 0 {
		return entry.MinBytes
	}
	return int64(minDatBytes)
}

// geofileInstalled reports whether the core will find a usable copy of name, and
// where.
//
// Size is checked, not just existence. The panel used to write downloads
// straight into the destination, so a run killed mid-transfer left a truncated
// .dat with a fresh mtime: present to os.Stat, fatal to the core, and immune to
// the Geofiles button because the fresh mtime made every later conditional GET
// answer 304. Treating short files as absent is what lets them be repaired.
func geofileInstalled(name string) (path string, ok bool) {
	if !isSafeGeofileName(name) {
		return resolveExoticGeofile(name)
	}
	floor := minBytesFor(name)
	dirs := append([]string{config.GetBinFolderPath()}, fallbackAssetDirs...)
	for _, dir := range dirs {
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Size() >= floor {
			return candidate, true
		}
	}
	return "", false
}

// resolveExoticGeofile handles a reference the panel cannot manage but the core
// can still open: `ext:geo/ir.dat:ir`, or a name with no .dat suffix. The core
// applies no filename rule at all (common/geodata checkFile just joins and
// opens), so refusing to look would mean calling a working config broken.
// Traversal is still refused: the resolved path must stay inside the asset dir.
func resolveExoticGeofile(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	dirs := append([]string{config.GetBinFolderPath()}, fallbackAssetDirs...)
	for _, dir := range dirs {
		root, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		candidate, err := filepath.Abs(filepath.Join(root, name))
		if err != nil {
			continue
		}
		if candidate != root && !strings.HasPrefix(candidate, root+string(os.PathSeparator)) {
			continue // escapes the asset dir
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Size() >= int64(minDatBytes) {
			return candidate, true
		}
	}
	return "", false
}

// extGeoPrefixes are the reference forms Xray accepts for an external geo file.
// They mirror common/geodata/rule_parser.go in the pinned core.
var extGeoPrefixes = [...]string{"ext:", "ext-ip:", "ext-domain:"}

// shorthandGeoFiles are the two prefixes the core rewrites to a fixed file
// before parsing (`geoip:cn` becomes `ext:geoip.dat:cn`), so a rule using them
// needs that file on disk just as much as an explicit ext: reference does.
var shorthandGeoFiles = map[string]string{
	"geoip:":   "geoip.dat",
	"geosite:": "geosite.dat",
}

// extGeoFileRef returns the file a single token points at, or "" when the token
// does not name one. The returned name is NOT validated: an ext-shaped token
// naming something this package cannot manage still has to reach the caller, or
// a config that kills the core would sail through unmentioned.
//
// Leading '!' is stripped the way the core's cutReversePrefix does. That is only
// strictly correct for IP rules (ParseDomainRules never calls it, so `!ext:...`
// in a domain list is a literal domain), and it is deliberate: this scanner
// over-approximates on purpose. A false positive costs one download of a file
// that really does exist upstream; a false negative costs the whole core.
func extGeoFileRef(token string) string {
	s := strings.TrimLeft(token, "!")
	for prefix, file := range shorthandGeoFiles {
		if strings.HasPrefix(s, prefix) {
			return file
		}
	}
	for _, prefix := range extGeoPrefixes {
		if !strings.HasPrefix(s, prefix) {
			continue
		}
		file, _, ok := strings.Cut(s[len(prefix):], ":")
		if !ok || file == "" {
			return ""
		}
		return file
	}
	return ""
}

// ExtGeoRefs walks Xray config JSON and returns every geo data file it
// references, de-duplicated and sorted.
//
// It walks whole documents, values and object KEYS alike, rather than reaching
// into the fields the rule editor writes. The core accepts these references in
// more places than the editor offers: routing rules, DNS server domains,
// per-inbound sniffing exclusions, freedom outbound ipsBlocked, and
// `dns.hosts`, where the reference is the object key rather than its value
// (infra/conf HostsWrapper.Build runs ParseDomainRule over each key). The
// reference nobody thought to look at is exactly the one that takes the core
// down at start.
func ExtGeoRefs(sections ...[]byte) []string {
	seen := make(map[string]struct{})
	note := func(token string) {
		if file := extGeoFileRef(token); file != "" {
			seen[file] = struct{}{}
		}
	}

	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			note(t)
		case []any:
			for _, item := range t {
				walk(item)
			}
		case map[string]any:
			for key, item := range t {
				note(key)
				walk(item)
			}
		}
	}

	for _, raw := range sections {
		if len(raw) == 0 {
			continue
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue // not our problem here; config validation reports it
		}
		walk(doc)
	}

	refs := make([]string, 0, len(seen))
	for file := range seen {
		refs = append(refs, file)
	}
	sort.Strings(refs)
	return refs
}

// EnsureGeofiles makes every referenced geo data file exist before Xray is
// handed a config that names it, downloading the ones the panel knows a source
// for. It returns what it fetched and what is still absent afterwards.
//
// A missing geo file is not a soft failure in the core. `ext:geoip_IR.dat:ir`
// with no geoip_IR.dat on disk aborts config parsing outright ("failed to load
// config files"), so the process never comes up and every inbound goes with it,
// not just the rule that named the file.
//
// Files outside builtinGeofiles are reported as missing rather than fetched:
// those belong to CustomGeoService, which has its own source URL per alias and
// has already had its turn in EnsureOnStartup.
func EnsureGeofiles(refs []string) (fetched []string, missing []string) {
	return ensureGeofiles(refs, false)
}

// EnsureGeofilesAuto is EnsureGeofiles for the paths nobody asked for by hand.
// It throttles repeat attempts at a file that has just failed, and caps how long
// any one download may run, because its caller holds the Xray restart lock.
func EnsureGeofilesAuto(refs []string) (fetched []string, missing []string) {
	return ensureGeofiles(refs, true)
}

func ensureGeofiles(refs []string, auto bool) (fetched []string, missing []string) {
	maxTime := geofileManualMaxTime
	if auto {
		maxTime = geofileAutoMaxTime
	}
	for _, name := range refs {
		if _, ok := geofileInstalled(name); ok {
			continue
		}
		entry, known := builtinGeofiles[name]
		if !known {
			missing = append(missing, name)
			continue
		}
		if auto && !autoFetchAllowed(name) {
			missing = append(missing, name)
			continue
		}
		logger.Info("geofile", name, "is referenced by the Xray config but not installed, downloading it")
		if err := downloadGeofile(entry, maxTime); err != nil {
			logger.Warningf("geofile %s: download failed: %v", name, err)
			// Re-stamp: the cooldown should run from when this attempt ENDED, not
			// from when it started, or a long failure gets no throttle at all.
			markAutoFetchAttempt(name)
			missing = append(missing, name)
			continue
		}
		clearAutoFetchCooldown(name)
		logger.Info("geofile", name, "downloaded")
		fetched = append(fetched, name)
	}
	return fetched, missing
}

// geofileAutoRetryCooldown is how long an automatic download of one file waits
// after an attempt before trying that file again.
const geofileAutoRetryCooldown = 10 * time.Minute

var (
	geofileAutoRetryMu sync.Mutex
	geofileAutoRetryAt = map[string]time.Time{}
)

// autoFetchAllowed rate-limits the automatic download of a single geo file, and
// records the attempt when it says yes.
//
// Without it, a file that simply cannot be fetched (no usable route to GitHub,
// which is the situation on a fair number of the servers this panel runs on)
// becomes a download attempt every few seconds, forever: the core refuses to
// start without the file, the health job sees it down and restarts it once a
// second, and every restart arrives back here. The Geofiles button never takes
// this path, so an operator can still force a retry at any time.
func autoFetchAllowed(name string) bool {
	geofileAutoRetryMu.Lock()
	defer geofileAutoRetryMu.Unlock()
	if last, seen := geofileAutoRetryAt[name]; seen && time.Since(last) < geofileAutoRetryCooldown {
		return false
	}
	geofileAutoRetryAt[name] = time.Now()
	return true
}

func markAutoFetchAttempt(name string) {
	geofileAutoRetryMu.Lock()
	defer geofileAutoRetryMu.Unlock()
	geofileAutoRetryAt[name] = time.Now()
}

func clearAutoFetchCooldown(name string) {
	geofileAutoRetryMu.Lock()
	defer geofileAutoRetryMu.Unlock()
	delete(geofileAutoRetryAt, name)
}

var (
	geofileDownloadMu    sync.Mutex
	geofileDownloadLocks = map[string]*sync.Mutex{}
)

// geofileDownloadLock serializes downloads of one file across the whole process.
//
// Concurrency here is ordinary, not exotic: the restart path and the Geofiles
// button are independent, and an operator who gets no response from a 74MB save
// will click Save again. Without this, each attempt starts its own full transfer
// into its own temp file, so N impatient clicks means N x 74MB written into bin/
// at once, which fills a small VPS.
func geofileDownloadLock(name string) *sync.Mutex {
	geofileDownloadMu.Lock()
	defer geofileDownloadMu.Unlock()
	mu, ok := geofileDownloadLocks[name]
	if !ok {
		mu = &sync.Mutex{}
		geofileDownloadLocks[name] = mu
	}
	return mu
}

// downloadGeofile fetches one geo data file into bin/, skipping the transfer
// when the local copy is already current (conditional GET on its mtime).
//
// maxTime caps the whole transfer; 0 means no cap. A stall guard applies either
// way, so a connection that stops delivering bytes fails instead of hanging.
//
// The body lands in a temp file that is renamed into place only once it is
// complete and has passed the size floor, because the destination is a file the
// core parses at startup: a partial write there fails exactly like a missing
// file, and its fresh mtime then makes every later conditional GET answer 304,
// so the Geofiles button reports success forever while the core stays down.
func downloadGeofile(entry geofileEntry, maxTime time.Duration) error {
	if !isSafeGeofileName(entry.FileName) {
		return common.NewErrorf("Invalid geofile name: %q", entry.FileName)
	}
	mu := geofileDownloadLock(entry.FileName)
	mu.Lock()
	defer mu.Unlock()

	binDir := config.GetBinFolderPath()
	destPath := filepath.Join(binDir, entry.FileName)
	floor := minBytesFor(entry.FileName)

	// Healthy enough to ask "has it changed?"; otherwise ask for the whole thing.
	// A truncated local copy must never send If-Modified-Since, or the 304 it
	// earns is what makes the damage permanent.
	localUsable := false
	if info, err := os.Stat(destPath); err == nil && !info.IsDir() && info.Size() >= floor {
		localUsable = true
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if maxTime > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, maxTime)
		defer stop()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, entry.URL, nil)
	if err != nil {
		return common.NewErrorf("Failed to create HTTP request for %s: %v", entry.URL, err)
	}
	if localUsable {
		if info, statErr := os.Stat(destPath); statErr == nil && !info.ModTime().IsZero() {
			req.Header.Set("If-Modified-Since", info.ModTime().UTC().Format(http.TimeFormat))
		}
	}

	resp, err := geofileHTTPClient.Do(req)
	if err != nil {
		return common.NewErrorf("Failed to download Geofile from %s: %v", entry.URL, err)
	}
	defer resp.Body.Close()

	var serverModTime time.Time
	if raw := resp.Header.Get("Last-Modified"); raw != "" {
		if parsed, parseErr := time.Parse(http.TimeFormat, raw); parseErr != nil {
			logger.Warningf("Failed to parse Last-Modified header for %s: %v", entry.URL, parseErr)
		} else {
			serverModTime = parsed
		}
	}
	stampModTime := func() {
		if serverModTime.IsZero() {
			return
		}
		if err := os.Chtimes(destPath, serverModTime, serverModTime); err != nil {
			logger.Warningf("Failed to update modification time for %s: %v", destPath, err)
		}
	}

	if resp.StatusCode == http.StatusNotModified {
		// Only trustworthy if the local copy is actually there. An unsolicited 304
		// (an intercepting proxy) would otherwise report success with no file.
		if !localUsable {
			return common.NewErrorf("Failed to download Geofile from %s: 304 with no usable local copy", entry.URL)
		}
		stampModTime()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return common.NewErrorf("Failed to download Geofile from %s: received status code %d", entry.URL, resp.StatusCode)
	}
	// A captive portal or a rate-limit page answers 200 with HTML. Renaming that
	// over a geo file leaves something that satisfies every presence check and
	// still refuses to parse.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		if strings.HasPrefix(ct, "text/") || strings.HasPrefix(ct, "application/json") {
			return common.NewErrorf("Failed to download Geofile from %s: server returned %s, not geo data", entry.URL, ct)
		}
	}

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return common.NewErrorf("Failed to create bin folder for %s: %v", destPath, err)
	}
	sweepStaleGeofileTemps()
	// A unique temp name, not "<dest>.tmp": on one shared path a second writer
	// truncates what the first is still writing and both then rename a corrupt
	// file into place. The per-file lock above already serializes our own callers;
	// this also covers an older panel process still finishing a download.
	tmp, err := os.CreateTemp(binDir, entry.FileName+".*.tmp")
	if err != nil {
		return common.NewErrorf("Failed to create Geofile %s: %v", destPath, err)
	}
	tmpPath := tmp.Name()

	// Abort a transfer that has stopped making progress. maxTime alone would let a
	// dead-but-open socket hold the caller for its whole budget.
	stall := time.AfterFunc(geofileStallTimeout, cancel)
	written, err := io.Copy(tmp, &stallWatchReader{r: resp.Body, tick: func() {
		stall.Reset(geofileStallTimeout)
	}})
	stall.Stop()

	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil && written < floor {
		err = common.NewErrorf("downloaded %d bytes, below the %d-byte floor for this file", written, floor)
	}
	if err == nil {
		// CreateTemp makes the file 0600; the geo files are 0644 like the rest of bin/.
		err = os.Chmod(tmpPath, 0o644)
	}
	if err != nil {
		os.Remove(tmpPath)
		return common.NewErrorf("Failed to save Geofile %s: %v", destPath, err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return common.NewErrorf("Failed to save Geofile %s: %v", destPath, err)
	}

	stampModTime()
	return nil
}

// stallWatchReader reports that bytes arrived, so a stall timer can be reset.
type stallWatchReader struct {
	r    io.Reader
	tick func()
}

func (s *stallWatchReader) Read(b []byte) (int, error) {
	n, err := s.r.Read(b)
	if n > 0 {
		s.tick()
	}
	return n, err
}

// staleGeofileTempAge is how old a leftover download temp must be before it is
// assumed dead. Comfortably longer than any live transfer can idle for, given
// the stall guard above.
const staleGeofileTempAge = time.Hour

// sweepStaleGeofileTemps deletes abandoned geo download temps.
//
// A panel killed mid-download leaves its temp behind, and these are large: a
// partial geosite_RU.dat is up to ~74MB. Every temp is swept, not just the one
// for the file being fetched, or a temp for a file nobody downloads again is
// never reclaimed. Age-gated, because a temp file that is minutes old may belong
// to a download running right now and unlinking it turns a working transfer into
// a failed rename.
func sweepStaleGeofileTemps() {
	matches, err := filepath.Glob(filepath.Join(config.GetBinFolderPath(), "*.dat.*.tmp"))
	if err != nil {
		return
	}
	for _, path := range matches {
		info, statErr := os.Stat(path)
		if statErr != nil || time.Since(info.ModTime()) < staleGeofileTempAge {
			continue
		}
		if rmErr := os.Remove(path); rmErr != nil {
			logger.Warningf("geofile: could not remove stale download temp %s: %v", path, rmErr)
		}
	}
}

// GeofileState is one row of the dashboard's Geofiles list.
type GeofileState struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Bundled   bool   `json:"bundled"`
	Size      int64  `json:"size"`
	UpdatedAt int64  `json:"updatedAt"`
}

// GetGeofileStatus reports which geo files are actually usable on disk, so the
// dashboard can say so instead of offering six identical-looking rows.
func (s *ServerService) GetGeofileStatus() []GeofileState {
	states := make([]GeofileState, 0, len(builtinGeofileOrder))
	for _, name := range builtinGeofileOrder {
		// Asked of corebundle rather than assumed: a GEO_LEAN=1 build carries only
		// the base pair, and a hardcoded list would then claim files ship with a
		// panel that never had them.
		state := GeofileState{Name: name, Bundled: corebundle.HasGeofile(name)}
		if path, ok := geofileInstalled(name); ok {
			state.Installed = true
			if info, err := os.Stat(path); err == nil {
				state.Size = info.Size()
				state.UpdatedAt = info.ModTime().Unix()
			}
		}
		states = append(states, state)
	}
	return states
}
