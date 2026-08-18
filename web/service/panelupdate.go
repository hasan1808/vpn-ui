package service

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/logger"
)

// panelUpdateInFlight guards against a second UpdatePanel running concurrently
// (e.g. a proxy 504 makes the browser retry while the first is still downloading),
// which would race on the ".new" temp path and the binary swap.
var panelUpdateInFlight atomic.Bool

// ErrPanelUpdateCancelled reports an update the user aborted. It is not a failure:
// the controller reports it as a success so the overview resets quietly instead of
// flashing an error toast and a red bar.
var ErrPanelUpdateCancelled = errors.New("panel update cancelled")

// panelUpdateCancel aborts the in-flight download. Guarded by its mutex because
// UpdatePanel (one request goroutine) publishes it while CancelPanelUpdate
// (another) reads it. Nil whenever no download is cancellable.
var (
	panelUpdateCancelMu sync.Mutex
	panelUpdateCancel   context.CancelFunc
)

// Panel self-update. The panel binary ships as a single GitHub release asset
// (hasan1808/vpn-ui, "vpn-ui-amd64") — the same source deploy.sh installs from — so
// the overview can both check for and apply updates in place.
//
// PanelAsset and PanelDownloadURL are exported because `vpn-ui-amd64 update` (the
// CLI/menu updater in main.go) installs from the very same release asset. It
// reuses these plus DownloadPanelUpdate/IsCompatibleBinary rather than reaching
// for UpdatePanel: that path ends in restartPanel, whose no-systemd branch
// syscall.Exec's os.Args back into itself. That is harmless for the panel, but from
// a CLI process it would re-exec the CLI with its own `update` arguments, in a loop.
const (
	panelRepo      = "hasan1808/vpn-ui"
	PanelAsset     = "vpn-ui-amd64"
	panelLatestAPI = "https://api.github.com/repos/" + panelRepo + "/releases/latest"
	// PanelDownloadURL is the release asset both the in-panel updater and the CLI
	// `update` subcommand download.
	PanelDownloadURL = "https://github.com/" + panelRepo + "/releases/latest/download/" + PanelAsset
	// PanelDownloadGZURL is the same asset gzip-compressed (~3x smaller). The
	// self-updater prefers it: over a slow or throttled link (Iran, China, …) the
	// compressed transfer finishes far sooner and is decompressed on the server.
	// Shipped alongside the raw binary by the release workflow.
	PanelDownloadGZURL = PanelDownloadURL + ".gz"
)

// PanelUpdateInfo reports the running version vs. the latest published release,
// plus the release notes the overview shows before an operator commits to
// installing.
type PanelUpdateInfo struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	// Notes is the release body as published (Markdown). Empty when GitHub was
	// unreachable or the release carries no notes; the dialog says so rather
	// than pretending there was nothing to report.
	Notes string `json:"notes"`
	// PublishedAt is the release timestamp (RFC 3339, as GitHub sends it), and
	// URL links to the release page for the full text.
	PublishedAt string `json:"publishedAt"`
	URL         string `json:"url"`
}

// panelNotesLimit caps how much release text is kept. The panel's own notes are
// a few lines; anything beyond this is a release that pasted a changelog, and
// the dialog is not where that belongs.
const panelNotesLimit = 16 << 10

// CheckPanelUpdate queries GitHub for the latest release tag and compares it to
// the running version. Best-effort and short-timeout: it runs on every overview
// load, so a slow/unreachable GitHub must not hang the dashboard.
func (s *ServerService) CheckPanelUpdate() (*PanelUpdateInfo, error) {
	cur := config.GetVersion()
	info := &PanelUpdateInfo{Current: cur, Latest: cur}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, panelLatestAPI, nil)
	if err != nil {
		return info, err
	}
	req.Header.Set("User-Agent", "vpn-ui") // GitHub API rejects requests without a UA
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return info, err
	}
	var rel Release
	if err := json.Unmarshal(body, &rel); err != nil {
		return info, err
	}

	latest := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	if latest != "" {
		info.Latest = latest
	}
	info.Available = versionNewer(latest, cur)

	notes := strings.TrimSpace(rel.Body)
	if len(notes) > panelNotesLimit {
		notes = notes[:panelNotesLimit] + "\n..."
	}
	info.Notes = notes
	info.PublishedAt = rel.PublishedAt
	info.URL = rel.HTMLURL
	return info, nil
}

// Self-update phases, as polled by the overview.
const (
	updatePhaseDownloading = "downloading"
	// Between the last byte and the staged confirmation: the ELF and build-info
	// checks, plus a -v probe that has to exec a ~300MB binary. Only the URL fetch
	// publishes it; the upload path reaches the same state client-side, where the
	// browser is the end that knows its last byte has gone out.
	updatePhaseChecking = "checking"
	// Downloaded and accepted, waiting on the operator's confirmation. Terminal for
	// the fetch request itself: nothing further happens until they answer.
	updatePhaseStaged     = "staged"
	updatePhaseInstalling = "installing"
	updatePhaseRestarting = "restarting"
	updatePhaseCancelled  = "cancelled"
	updatePhaseError      = "error"
)

// Self-update progress, polled by the overview to render a % bar and a speed
// readout. percent is the download percent (0-99 while downloading, 100 once the
// restart is armed). bytes/total/speed describe the download only; total is 0 when
// the server sends no Content-Length, in which case there is no percent either.
var (
	panelUpdatePercent atomic.Int32
	panelUpdatePhase   atomic.Value // string
	panelUpdateBytes   atomic.Int64
	panelUpdateTotal   atomic.Int64
	panelUpdateSpeed   atomic.Int64 // bytes/sec
)

func setUpdateProgress(phase string, percent int32) {
	panelUpdatePhase.Store(phase)
	panelUpdatePercent.Store(percent)
}

// resetUpdateCounters clears the download counters so a fresh attempt can't briefly
// report the previous one's bytes and speed before its first Read lands.
func resetUpdateCounters() {
	panelUpdateBytes.Store(0)
	panelUpdateTotal.Store(0)
	panelUpdateSpeed.Store(0)
}

// PanelUpdateProgressInfo is the live self-update state polled by the overview.
type PanelUpdateProgressInfo struct {
	Phase   string `json:"phase"`
	Percent int    `json:"percent"`
	Bytes   int64  `json:"bytes"`
	Total   int64  `json:"total"`
	Speed   int64  `json:"speed"` // bytes/sec
	// Running distinguishes "a download is happening right now" from "phase still
	// holds whatever the last attempt left behind". The phase alone cannot answer
	// that: error and cancelled are written once by the deferred block in
	// UpdatePanel and then never cleared for the life of the process, so an
	// overview that reopened hours later would read a stale terminal phase as live
	// work. This is what lets the page re-attach to an update it did not start -
	// the download outlives the request that began it, because its context is
	// context.Background() and Gin does not kill a handler when the browser leaves.
	Running bool `json:"running"`
}

// PanelUpdateProgress returns the current self-update phase and download counters.
func (s *ServerService) PanelUpdateProgress() PanelUpdateProgressInfo {
	phase, _ := panelUpdatePhase.Load().(string)
	return PanelUpdateProgressInfo{
		Phase:   phase,
		Percent: int(panelUpdatePercent.Load()),
		Bytes:   panelUpdateBytes.Load(),
		Total:   panelUpdateTotal.Load(),
		Speed:   panelUpdateSpeed.Load(),
		Running: panelUpdateInFlight.Load(),
	}
}

// PanelUpdateResultInfo is the answer to "did this panel just come back from an
// in-panel update, and from what version".
type PanelUpdateResultInfo struct {
	Updated bool   `json:"updated"`
	From    string `json:"from"`
	To      string `json:"to"`
	// Where the pre-update database snapshot landed. Empty when the snapshot did
	// not run or failed, which it is allowed to do: it is best-effort and does not
	// block the update.
	BackupPath string `json:"backupPath"`
}

// TakePanelUpdateResult reports whether this process is the one that came up
// after a self-update, CONSUMING the record so the news is delivered once.
//
// To is always this binary's version, so the caller can render the notice without
// a second round trip. From can equal To when the operator reinstalled the version
// they were already on; that is still a completed update and is reported as one.
func (s *ServerService) TakePanelUpdateResult() PanelUpdateResultInfo {
	var settingService SettingService
	from := settingService.TakePanelUpdatedFrom()
	return PanelUpdateResultInfo{
		Updated:    from != "",
		From:       from,
		To:         config.GetVersion(),
		BackupPath: settingService.TakePanelUpdateBackupPath(),
	}
}

// speedSampleInterval bounds how often the published speed is recomputed, and
// speedEMAAlpha weights each new sample against the running average. Raw per-Read
// deltas are far too bursty to show verbatim: TCP delivers in chunks, so an
// unsmoothed readout swings wildly between 0 and multiples of the true rate.
const (
	speedSampleInterval = 500 * time.Millisecond
	speedEMAAlpha       = 0.3
)

// progressReader tallies bytes read from the download so the overview can show a
// live % bar and speed readout via the PanelUpdateProgress poll. Counters are
// published to atomics rather than exposed as fields: only the download goroutine
// touches the fields, while poll handlers read the atomics concurrently.
type progressReader struct {
	r     io.Reader
	total int64
	read  int64

	lastSampleAt    time.Time
	lastSampleBytes int64
}

func newProgressReader(r io.Reader, total int64) *progressReader {
	if total < 0 {
		total = 0 // unknown length (chunked): still count bytes, just skip percent
	}
	panelUpdateTotal.Store(total)
	return &progressReader{r: r, total: total, lastSampleAt: time.Now()}
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 {
		pr.read += int64(n)
		panelUpdateBytes.Store(pr.read)
		if pr.total > 0 {
			if pct := pr.read * 99 / pr.total; pct >= 0 && pct <= 99 {
				panelUpdatePercent.Store(int32(pct))
			}
		}
		pr.sampleSpeed(time.Now())
	}
	return n, err
}

// sampleSpeed republishes the download rate at most once per speedSampleInterval,
// smoothing each sample into the previous value.
func (pr *progressReader) sampleSpeed(now time.Time) {
	elapsed := now.Sub(pr.lastSampleAt)
	if elapsed < speedSampleInterval {
		return
	}
	bps := float64(pr.read-pr.lastSampleBytes) / elapsed.Seconds()
	if prev := panelUpdateSpeed.Load(); prev > 0 {
		bps = speedEMAAlpha*bps + (1-speedEMAAlpha)*float64(prev)
	}
	panelUpdateSpeed.Store(int64(bps))
	pr.lastSampleAt, pr.lastSampleBytes = now, pr.read
}

// UpdatePanel downloads the latest release binary, snapshots the DB, atomically
// replaces the running executable, and restarts the panel so the new binary takes
// over. Replacing a running ELF via rename is safe on Linux: the live process keeps
// the old (now-unlinked) inode, and the next start execs the new file.
func (s *ServerService) UpdatePanel() error {
	if !panelUpdateInFlight.CompareAndSwap(false, true) {
		return fmt.Errorf("a panel update is already in progress")
	}
	resetUpdateCounters()
	setUpdateProgress(updatePhaseDownloading, 0)

	// Scope a cancellable context to the download so CancelPanelUpdate can abort a
	// slow or stalled transfer. Publishing it under the mutex is what gives the
	// cancel endpoint something to signal.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setPanelUpdateCancel(cancel)

	// Reset the guard on every early/error return. On success we intentionally leave
	// it set: restartPanel is about to replace this process, so the in-memory flag
	// dies with it (and blocks a duplicate update during the restart window).
	restarting := false
	cancelled := false
	defer func() {
		setPanelUpdateCancel(nil)
		if !restarting {
			panelUpdateSpeed.Store(0)
			if cancelled {
				setUpdateProgress(updatePhaseCancelled, 0)
			} else {
				setUpdateProgress(updatePhaseError, 0)
			}
			// Released LAST. A second attempt that wins the CAS in between would have
			// its fresh "downloading" phase clobbered by the terminal one above.
			panelUpdateInFlight.Store(false)
		}
	}()

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve own path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	tmp := exe + ".new"
	logger.Infof("panel update: downloading %s", PanelDownloadURL)
	if err := DownloadPanelBinary(ctx, tmp, PanelDownloadURL); err != nil {
		_ = os.Remove(tmp)
		// A cancelled download surfaces as a transport error; ctx is what says the
		// user asked for it rather than the network failing.
		if ctx.Err() != nil {
			cancelled = true
			logger.Info("panel update: cancelled by user during download")
			return ErrPanelUpdateCancelled
		}
		return err
	}
	// Validate it's an ELF for THIS architecture — a 404 HTML page, a truncated
	// file, or a wrong-arch asset would otherwise be renamed over the running binary
	// and brick the panel (the restart would fail with exec-format-error).
	if !IsCompatibleBinary(tmp) {
		_ = os.Remove(tmp)
		return fmt.Errorf("downloaded file is not a %s Linux binary (no valid '%s' asset?)", runtime.GOARCH, PanelAsset)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	// A cancel can land between the download returning and the hook being dropped
	// below. ctx is not consulted anywhere after DownloadPanelBinary, so without
	// this the user would get an HTTP success for their cancel and be updated
	// anyway. Checked before the install starts, which is the last moment aborting
	// is free.
	if ctx.Err() != nil {
		_ = os.Remove(tmp)
		cancelled = true
		logger.Info("panel update: cancelled by user just before installing")
		return ErrPanelUpdateCancelled
	}

	if err := installPanelBinary(tmp, exe); err != nil {
		return err
	}
	// Set only once the swap succeeded, so the deferred reset above still publishes
	// the error phase for every path that did not get this far.
	restarting = true
	return nil
}

// installPanelBinary is the point of no return, shared by the download updater and
// the update-from-file path: snapshot the DB, keep a rollback copy of the running
// binary, swap `staged` in, record what was replaced, and restart. One
// implementation because this is the sequence that must not be interrupted
// half-way, and two copies of it would be two chances to get the order wrong.
//
// Replacing a running ELF via rename is safe on Linux: the live process keeps the
// old (now-unlinked) inode, and the next start execs the new file.
func installPanelBinary(staged, exe string) error {
	setUpdateProgress(updatePhaseInstalling, 99)
	// Drop the cancel hook: a nil hook is what makes CancelPanelUpdate refuse from
	// here on.
	setPanelUpdateCancel(nil)
	panelUpdateSpeed.Store(0)
	// Best-effort DB snapshot before the new binary can migrate it. The path is kept
	// so the notice the restarted panel shows can say where the old database went.
	backupPath, _ := backupPanelDB()

	// Keep a copy of the current binary next to it so a bad update can be rolled
	// back manually (mv vpn-ui.bak vpn-ui): once renamed, the old inode is gone.
	if err := CopyFile(exe, exe+".bak"); err == nil {
		_ = os.Chmod(exe+".bak", 0o755)
	} else {
		logger.Warning("panel update: binary backup failed (continuing):", err)
	}

	if err := os.Rename(staged, exe); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("replacing binary failed: %w", err)
	}
	logger.Infof("panel update: installed new binary at %s, restarting", exe)
	setUpdateProgress(updatePhaseRestarting, 100)

	// Record what we are replacing so the binary that comes up can tell the
	// operator the update landed. Written here, after the swap and before the
	// restart, so it marks a self-update specifically and not any other restart.
	// Best-effort: a panel that cannot write this still updates fine, it just
	// comes back without the notice.
	var settingService SettingService
	if err := settingService.SetPanelUpdatedFrom(config.GetVersion()); err != nil {
		logger.Warning("panel update: recording the updated-from version failed:", err)
	}
	// Written even when the snapshot failed and the path is empty: this CLEARS an
	// earlier update's path, which would otherwise be announced as this one's.
	if err := settingService.SetPanelUpdateBackupPath(backupPath); err != nil {
		logger.Warning("panel update: recording the DB backup path failed:", err)
	}

	// Restart detached so our own termination can't abort the restart.
	go restartPanel(exe)
	return nil
}

// setPanelUpdateCancel publishes (or clears) the hook CancelPanelUpdate signals.
func setPanelUpdateCancel(cancel context.CancelFunc) {
	panelUpdateCancelMu.Lock()
	panelUpdateCancel = cancel
	panelUpdateCancelMu.Unlock()
}

// CancelPanelUpdate aborts an in-flight download. Only the download is cancellable:
// once installing starts, the DB snapshot and the binary swap have to run to
// completion, so a late cancel is refused rather than risk a half-swapped panel.
func (s *ServerService) CancelPanelUpdate() error {
	if !panelUpdateInFlight.Load() {
		return fmt.Errorf("no panel update is in progress")
	}
	panelUpdateCancelMu.Lock()
	cancel := panelUpdateCancel
	panelUpdateCancelMu.Unlock()
	// A nil hook IS the gate: UpdatePanel drops it the moment it starts installing.
	if cancel == nil {
		return fmt.Errorf("the update is already installing and can no longer be cancelled")
	}
	logger.Info("panel update: cancel requested")
	cancel()
	return nil
}

// DownloadPanelBinary streams url into dst (0755), aborting if ctx is cancelled.
func DownloadPanelBinary(ctx context.Context, dst, url string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vpn-ui")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, url)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()
	// Feed the overview's % bar and speed readout. Attached even when the length is
	// unknown: bytes and speed are still meaningful, only the percent isn't.
	if _, err := io.Copy(f, newProgressReader(resp.Body, resp.ContentLength)); err != nil {
		return err
	}
	return nil
}

// elfMachineFor maps a GOARCH to its ELF e_machine value (little-endian targets
// only). The bool is false for archs we don't map, in which case only the ELF magic
// is checked (still catches an HTML 404 page, just not a wrong-arch binary).
func elfMachineFor(goarch string) (uint16, bool) {
	switch goarch {
	case "amd64":
		return 0x3E, true // EM_X86_64
	case "arm64":
		return 0xB7, true // EM_AARCH64
	case "386":
		return 0x03, true // EM_386
	case "arm":
		return 0x28, true // EM_ARM
	}
	return 0, false
}

// IsCompatibleBinary reports whether path is an ELF whose architecture matches the
// running panel. Guards against installing an HTML error page, a truncated file, or
// a wrong-architecture asset over the live binary (which would brick the restart).
func IsCompatibleBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [20]byte // magic(4) + ident(12) + e_type(2) + e_machine(2)
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	if hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F' {
		return false
	}
	if hdr[5] != 1 { // EI_DATA: only little-endian targets are supported
		return false
	}
	machine := uint16(hdr[18]) | uint16(hdr[19])<<8
	if want, ok := elfMachineFor(runtime.GOARCH); ok && machine != want {
		return false
	}
	return true
}

// DownloadPanelUpdate fetches the panel release asset into exe+".new" and returns
// its path. It prefers the gzip-compressed asset and falls back to the raw binary
// (which is also the target for old releases that predate the .gz asset). Used by
// the CLI/menu updater (`vpn-ui-amd64 update`) in main.go.
func DownloadPanelUpdate(ctx context.Context, exe, version string) (string, error) {
	var gzURL, rawURL string
	if version == "" {
		gzURL = PanelDownloadGZURL
		rawURL = PanelDownloadURL
	} else {
		base := fmt.Sprintf("https://github.com/%s/releases/download/v%s/%s", panelRepo, version, PanelAsset)
		gzURL, rawURL = base+".gz", base
	}

	tmp := exe + ".new"
	if err := downloadGunzip(ctx, gzURL, tmp); err == nil {
		if IsCompatibleBinary(tmp) && HasSQLiteSupport(tmp) {
			return finalizeBinary(tmp)
		}
		_ = os.Remove(tmp)
		logger.Warningf("panel update: compressed asset from %s was invalid, falling back to raw binary", gzURL)
	} else if ctx.Err() != nil {
		return "", ctx.Err()
	}

	_ = os.Remove(tmp)
	if err := downloadPanelAsset(ctx, tmp, rawURL); err != nil {
		return "", err
	}
	if !IsCompatibleBinary(tmp) {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("downloaded file is not a %s Linux binary (no valid '%s' asset?)", runtime.GOARCH, PanelAsset)
	}
	if !HasSQLiteSupport(tmp) {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("downloaded binary lacks CGO/SQLite support — update via deploy.sh on the server instead")
	}
	return finalizeBinary(tmp)
}

// downloadGunzip fetches gzURL (resuming a partial file) and decompresses it into
// dst. The .gz is downloaded to a temp sibling first — resume operates on the
// compressed bytes, which is only valid at byte offsets if we keep the stream whole
// — then decompressed once complete.
func downloadGunzip(ctx context.Context, gzURL, dst string) error {
	gzTmp := dst + ".gz"
	if err := downloadPanelAsset(ctx, gzTmp, gzURL); err != nil {
		return err
	}
	if err := gunzipFile(gzTmp, dst); err != nil {
		_ = os.Remove(gzTmp)
		_ = os.Remove(dst)
		return err
	}
	_ = os.Remove(gzTmp)
	return nil
}

func gunzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		gz.Close()
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, gz); err != nil {
		gz.Close()
		return err
	}
	return gz.Close()
}

func finalizeBinary(tmp string) (string, error) {
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// downloadPanelAsset fetches url into dst, resuming from dst's existing size when the
// server supports byte ranges. A 416 (range not satisfiable) means the partial is
// already complete or stale: it is discarded and the download restarts. Progress is
// reported through the overview counters, including the already-present prefix on a
// resumed transfer so the % bar reflects the whole asset.
//
// No overall deadline: on a slow or throttled link (Iran, China, …) a whole-binary
// transfer can legitimately take well past any fixed cap, and an arbitrary timeout
// is what fails the user mid-transfer (context deadline exceeded while reading the
// body). panelFetchClient guards only the connection stages (dial / TLS / response
// headers) and lets ctx, via the cancel button, bound the actual download.
func downloadPanelAsset(ctx context.Context, dst, url string) error {
	client := panelFetchClient()

	var offset int64
	if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
		offset = fi.Size()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "pro-ui")
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		resp.Body.Close()
		_ = os.Remove(dst)
		return downloadPanelAsset(ctx, dst, url)
	}

	restart := resp.StatusCode == http.StatusOK
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, url)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()

	if restart {
		if err := f.Truncate(0); err != nil {
			return err
		}
		offset = 0
	} else if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	if _, err := io.Copy(f, newProgressReader(resp.Body, offset+resp.ContentLength)); err != nil {
		return err
	}
	return nil
}

// HasSQLiteSupport checks whether a Linux ELF binary was built with CGO_ENABLED=1,
// which is required for SQLite (mattn/go-sqlite3). A non-CGO binary will fail to
// open the database at startup, bricking the panel. The check works by looking for
// a PT_INTERP program header — statically-linked Go binaries (CGO_ENABLED=0) have
// none, while dynamically-linked ones (CGO_ENABLED=1) do.
func HasSQLiteSupport(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var ident [16]byte
	if _, err := io.ReadFull(f, ident[:]); err != nil {
		return false
	}
	if ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		return false
	}

	class := ident[4] // EI_CLASS: 1 = 32-bit, 2 = 64-bit
	var phoff uint64
	var phentsize, phnum uint16

	if class == 2 { // 64-bit ELF
		var ehdr [64]byte
		copy(ehdr[:16], ident[:])
		if _, err := io.ReadFull(f, ehdr[16:]); err != nil {
			return false
		}
		// e_phoff at byte 32, 8 bytes LE
		phoff = uint64(ehdr[32]) | uint64(ehdr[33])<<8 | uint64(ehdr[34])<<16 | uint64(ehdr[35])<<24 |
			uint64(ehdr[36])<<32 | uint64(ehdr[37])<<40 | uint64(ehdr[38])<<48 | uint64(ehdr[39])<<56
		// e_phentsize at byte 54, 2 bytes LE; e_phnum at byte 56, 2 bytes LE
		phentsize = uint16(ehdr[54]) | uint16(ehdr[55])<<8
		phnum = uint16(ehdr[56]) | uint16(ehdr[57])<<8
	} else { // 32-bit ELF
		var ehdr [52]byte
		copy(ehdr[:16], ident[:])
		if _, err := io.ReadFull(f, ehdr[16:]); err != nil {
			return false
		}
		// e_phoff at byte 28, 4 bytes LE
		phoff = uint64(ehdr[28]) | uint64(ehdr[29])<<8 | uint64(ehdr[30])<<16 | uint64(ehdr[31])<<24
		// e_phentsize at byte 42, 2 bytes LE; e_phnum at byte 44, 2 bytes LE
		phentsize = uint16(ehdr[42]) | uint16(ehdr[43])<<8
		phnum = uint16(ehdr[44]) | uint16(ehdr[45])<<8
	}

	if phentsize == 0 || phnum == 0 {
		return false
	}

	phdr := make([]byte, phentsize)
	for i := uint16(0); i < phnum; i++ {
		_, err := f.ReadAt(phdr, int64(phoff+uint64(i)*uint64(phentsize)))
		if err != nil {
			return false
		}
		// p_type at offset 0, 4 bytes LE
		ptype := uint32(phdr[0]) | uint32(phdr[1])<<8 | uint32(phdr[2])<<16 | uint32(phdr[3])<<24
		if ptype == 3 { // PT_INTERP
			return true
		}
	}
	return false
}

// backupPanelDB copies the SQLite DB (and its WAL/SHM sidecars) into a backups/
// directory beside it, named for the version being replaced, this panel's name and
// the moment it happened. Returns where it landed, or "" if it wrote nothing:
// best-effort, since a failed snapshot must not block the update.
//
// The timestamp is what makes this multi-slot. The name used to be the version
// alone, so a second update FROM the same version (a retry, or reinstalling the
// build you are already on) silently overwrote the only copy the operator had.
//
// Domain is left out of the name: there is no request behind this call, so it could
// only ever resolve to the webDomain setting or to nothing, and the panel name
// already says which install this came from.
func backupPanelDB() (string, error) {
	db := config.GetDBPath()
	if _, err := os.Stat(db); err != nil {
		return "", err
	}
	dir := filepath.Join(filepath.Dir(db), "backups")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// Fold the WAL into the main DB first so the file copy is a consistent snapshot
	// (the panel holds the DB open, so a plain copy could otherwise be torn).
	if gdb := database.GetDB(); gdb != nil {
		if sqlDB, err := gdb.DB(); err == nil {
			_, _ = sqlDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		}
	}
	// config.GetVersion() is still the OUTGOING version here: the swap has not
	// happened yet, and this process is the binary being replaced.
	var serverService ServerService
	base := serverService.BuildBackupFilename(BackupNameOptions{
		Date:      true,
		Time:      true,
		PanelName: true,
		Version:   true,
	}, "")
	dst := filepath.Join(dir, base)
	if err := CopyFile(db, dst); err != nil {
		logger.Warning("panel update: DB backup failed:", err)
		return "", err
	}
	for _, side := range []string{"-wal", "-shm"} {
		_ = CopyFile(db+side, dst+side)
	}
	logger.Infof("panel update: backed up DB -> %s", dst)
	return dst, nil
}

func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// restartPanel brings the new binary online. Under systemd (the deploy.sh setup)
// it triggers a detached `systemctl restart` that survives this process's death;
// otherwise it re-execs the freshly installed binary in place.
func restartPanel(exe string) {
	time.Sleep(1 * time.Second) // give the HTTP response time to flush

	// The re-exec below keeps the same PID, so execve does NOT kill our child
	// processes — a surviving Xray keeps holding 127.0.0.1:62790 and collides with the
	// new panel's fresh Xray ("address already in use"). Stop the supervised daemons
	// and Xray first so nothing orphans. Under systemd the cgroup kill also reaps them
	// (harmless here); the new panel's ReapOrphanXray is the crash-safe backstop for
	// when this stop is skipped (SIGKILL) or races.
	GetProcManager().StopAll()
	_ = (&XrayService{}).StopXray()

	var sd SystemdService
	name := sd.GetServiceName()
	if commandExists("systemctl") && systemctlActive(name) {
		// setsid detaches the restarter so systemd killing us mid-restart is fine.
		if err := exec.Command("setsid", "sh", "-c", fmt.Sprintf("sleep 1; systemctl restart %s", name)).Start(); err != nil {
			// The restart never launched: the binary is already swapped but this
			// process keeps running the old one. Release the guard so the operator
			// can retry from the panel (or restart the unit manually).
			logger.Warning("panel update: failed to launch restarter — retry the update or restart the unit manually:", err)
			panelUpdateInFlight.Store(false)
		}
		return
	}
	// No systemd: re-exec the new binary, replacing this process image.
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		logger.Warning("panel update: re-exec failed, exiting for supervisor restart:", err)
		os.Exit(0)
	}
}

// versionNewer reports whether dotted version a is strictly newer than b (both
// may carry a leading "v"). Non-numeric or unparseable tags yield false, so a
// malformed release never spuriously advertises an update.
func versionNewer(a, b string) bool {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	if a == "" {
		return false
	}
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}
