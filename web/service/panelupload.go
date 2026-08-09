package service

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/random"
)

// Manual update: the operator names a vpn-ui binary themselves, either by picking a
// file in the browser or by giving a URL the panel downloads, instead of fetching the
// release from GitHub. Same installer, same rollback copy, same restart; only the
// source of the bytes differs, which is why this ends in installPanelBinary rather than
// repeating the swap sequence, and why the two sources meet at StagePanelBinary rather
// than each growing their own copy of the checks.
//
// It is deliberately TWO requests. The first uploads and INSPECTS, and answers with the
// version it read out of the file itself; the second applies what inspection staged.
// Nothing is swapped until the operator has been shown real versions, so the
// confirmation is about the binary on disk rather than about a filename, which anyone
// can mistype.

const (
	// MaxPanelUploadSize caps an uploaded binary. The release asset is around 315MB
	// (it embeds Xray, the geo databases and every bundled daemon), so this leaves
	// room to grow while still refusing a body that could fill the filesystem the
	// panel's DB lives on.
	MaxPanelUploadSize = 1 << 30

	// Direction of the staged binary relative to the running one.
	PanelUploadUpgrade   = "upgrade"
	PanelUploadDowngrade = "downgrade"
	PanelUploadSame      = "same"
	PanelUploadUnknown   = "unknown"

	// A version probe should answer instantly; anything slower is not a vpn-ui binary
	// behaving normally and must not hold a request open.
	panelVersionProbeTimeout = 15 * time.Second
	panelVersionProbeMaxOut  = 4 << 10

	// How long a staged file waits for its apply call. The two steps are one operator
	// action seconds apart, so anything older is an abandoned upload: it gets deleted
	// rather than installed, and it is the size of a whole panel binary.
	stagedPanelTTL = 30 * time.Minute

	// How long a URL fetch may take end to end. Generous because the operator chose a
	// mirror this panel can actually reach, which on the networks this feature exists
	// for is often a slow one, and the asset is the better part of a gigabyte.
	panelURLFetchTimeout = 30 * time.Minute
)

// ErrNoStagedPanelBinary reports an apply with nothing staged: the upload failed, the
// panel restarted in between, or a second tab already consumed it.
var ErrNoStagedPanelBinary = errors.New("no uploaded binary is waiting to be applied")

// StagedPanelInfo is what the operator confirms against: both versions, which way the
// swap goes, and the token naming the exact file those versions were read from.
type StagedPanelInfo struct {
	Token     string `json:"token"`
	Current   string `json:"current"`
	New       string `json:"new"`
	Direction string `json:"direction"`
	Size      int64  `json:"size"`
}

// One staging slot, guarded. The token is what ties an apply call to the file the
// inspect call actually measured: without it, a second upload landing between the two
// steps would be installed under the first one's version report, which is precisely
// the confirmation this flow exists to make trustworthy.
var (
	stagedPanelMu   sync.Mutex
	stagedPanelPath string
	stagedPanelInfo StagedPanelInfo
	stagedPanelAt   time.Time
)

// panelVersionPattern is what a version line has to look like. It is the cheapest test
// that separates "a vpn-ui binary" from "some other ELF that printed its usage": the
// panel answers -v with a bare dotted version and nothing else.
var panelVersionPattern = regexp.MustCompile(`^v?\d+(\.\d+)*$`)

// StagePanelBinary writes an uploaded binary next to the running one, checks it is
// something this host can actually exec, reads its version, and holds it for a
// following apply. It does NOT install anything.
//
// The staging path is a sibling of the running binary so the eventual install is a
// rename within one filesystem, which is what makes the swap atomic. /tmp would not be:
// it is frequently a different mount, and os.Rename across mounts fails.
func StagePanelBinary(src io.Reader, declaredSize int64) (StagedPanelInfo, error) {
	var info StagedPanelInfo

	// Advisory only: a chunked upload declares nothing, and a client can lie. The real
	// enforcement is the LimitReader below, which counts what actually arrives.
	if declaredSize > MaxPanelUploadSize {
		return info, fmt.Errorf("that file is %s, larger than the %s limit",
			humanBytes(declaredSize), humanBytes(MaxPanelUploadSize))
	}
	// A download-driven update owns the same paths and ends in the same swap, so the
	// two must not overlap.
	if panelUpdateInFlight.Load() {
		return info, fmt.Errorf("a panel update is already in progress")
	}

	exe, err := panelExecutablePath()
	if err != nil {
		return info, err
	}
	staged := exe + ".upload"

	// Discard anything a previous attempt left behind before writing: a half-uploaded
	// file from a dropped connection must never be what a later apply installs.
	DiscardStagedPanelBinary()

	out, err := os.OpenFile(staged, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return info, fmt.Errorf("cannot stage the upload next to the panel binary: %w", err)
	}
	// One read limit past the cap, so a body that lies about its length is caught by
	// what actually arrived rather than by its Content-Length header.
	written, copyErr := io.Copy(out, io.LimitReader(src, MaxPanelUploadSize+1))
	closeErr := out.Close()
	switch {
	case copyErr != nil:
		_ = os.Remove(staged)
		return info, fmt.Errorf("upload failed: %w", copyErr)
	case closeErr != nil:
		_ = os.Remove(staged)
		return info, fmt.Errorf("upload failed: %w", closeErr)
	case written > MaxPanelUploadSize:
		_ = os.Remove(staged)
		return info, fmt.Errorf("that file is larger than the %s limit", humanBytes(MaxPanelUploadSize))
	case written == 0:
		_ = os.Remove(staged)
		return info, errors.New("that file is empty")
	}

	// Cheapest checks first, and nothing is executed until both have passed. Same gate
	// the downloader uses: a wrong-arch or non-ELF file renamed over the running binary
	// would brick the panel, because the restart fails with exec-format-error and there
	// is no longer a working binary to serve a retry.
	if !IsCompatibleBinary(staged) {
		_ = os.Remove(staged)
		return info, fmt.Errorf("that file is not a %s Linux binary", runtime.GOARCH)
	}
	if !HasSQLiteSupport(staged) {
		_ = os.Remove(staged)
		return info, fmt.Errorf("that binary lacks CGO/SQLite support — build with CGO_ENABLED=1")
	}
	// A pure parse, no execution: a shell script, a stripped C binary or somebody
	// else's ELF is refused before the probe below ever runs it.
	if !isGoBinary(staged) {
		_ = os.Remove(staged)
		return info, errors.New("that file is not a Go binary, so it is not a vpn-ui panel")
	}

	version, err := panelBinaryVersion(staged)
	if err != nil {
		_ = os.Remove(staged)
		return info, err
	}

	current := config.GetVersion()
	info = StagedPanelInfo{
		Token:     random.Seq(32),
		Current:   current,
		New:       version,
		Direction: comparePanelVersions(version, current),
		Size:      written,
	}

	stagedPanelMu.Lock()
	stagedPanelPath, stagedPanelInfo, stagedPanelAt = staged, info, time.Now()
	stagedPanelMu.Unlock()

	logger.Infof("panel update: staged an uploaded binary, v%s -> v%s (%s)",
		current, version, info.Direction)
	return info, nil
}

// ApplyStagedPanelBinary installs the file a previous StagePanelBinary accepted, named
// by the token that inspection returned, and restarts the panel. Returns once the
// restart has been handed off, exactly as UpdatePanel does.
func ApplyStagedPanelBinary(token string) error {
	stagedPanelMu.Lock()
	staged, info, at := stagedPanelPath, stagedPanelInfo, stagedPanelAt
	// Cleared up front, whatever happens next: a staged file must be installable
	// exactly once, so a double-submit cannot swap the binary twice.
	stagedPanelPath, stagedPanelInfo, stagedPanelAt = "", StagedPanelInfo{}, time.Time{}
	stagedPanelMu.Unlock()

	if staged == "" || info.Token == "" {
		return ErrNoStagedPanelBinary
	}
	// The token is not a secret, it only pins WHICH file the confirmation was about.
	// A mismatch still has to refuse: otherwise a second upload landing between
	// inspect and apply gets installed under the first one's version report, and the
	// operator confirmed a swap that is not the one happening.
	if token != info.Token {
		_ = os.Remove(staged)
		return errors.New("the staged upload no longer matches this confirmation, upload the file again")
	}
	if time.Since(at) > stagedPanelTTL {
		_ = os.Remove(staged)
		return fmt.Errorf("the uploaded binary expired after %s, upload it again", stagedPanelTTL)
	}
	if _, err := os.Stat(staged); err != nil {
		return ErrNoStagedPanelBinary
	}

	exe, err := panelExecutablePath()
	if err != nil {
		_ = os.Remove(staged)
		return err
	}

	if !panelUpdateInFlight.CompareAndSwap(false, true) {
		_ = os.Remove(staged)
		return fmt.Errorf("a panel update is already in progress")
	}
	resetUpdateCounters()

	// installPanelBinary hands off to a detached restart on success, so the in-flight
	// flag is left set on purpose: it dies with this process and blocks a duplicate
	// update during the restart window. Only a failure releases it.
	if err := installPanelBinary(staged, exe); err != nil {
		setUpdateProgress(updatePhaseError, 0)
		panelUpdateInFlight.Store(false)
		return err
	}
	logger.Infof("panel update: applied uploaded binary v%s", info.New)
	return nil
}

// StagePanelBinaryFromURL fetches a binary from an operator-supplied URL and stages it
// exactly as an upload does, so the confirmation and the apply step below are the same
// code for both manual sources. It exists for the box that cannot reach GitHub but can
// reach some other mirror: the release check is precisely what fails there, so an
// update path that does not depend on it has to name its own address.
//
// The bytes are handed straight to StagePanelBinary rather than downloaded to a file
// first: every check it makes (size cap, ELF magic, arch, Go build info, -v probe) is
// what a stranger's URL needs most, and duplicating the download would only add a
// second place for the staging path to drift.
//
// There is deliberately no private-address (SSRF) guard. The caller is already a super
// admin, which on this panel means "may replace the running binary and have it exec'd
// as root" -- the very next step of this flow. Refusing a 10.x mirror would block the
// air-gapped install this feature is for while stopping nothing an operator with these
// rights cannot do anyway.
func StagePanelBinaryFromURL(rawURL string) (StagedPanelInfo, error) {
	var info StagedPanelInfo

	target, err := validatePanelBinaryURL(rawURL)
	if err != nil {
		return info, err
	}
	// Checked before the transfer as well as inside StagePanelBinary, which only sees
	// it once the last byte has landed. Both guard the same clash, but finding out
	// after pulling several hundred megabytes is a long wait for an answer that was
	// available at the start.
	if panelUpdateInFlight.Load() {
		return info, fmt.Errorf("a panel update is already in progress")
	}

	// The ctx bounds the whole transfer; the transport below bounds the parts that
	// hang without transferring anything. A release asset is ~315MB, so a fixed
	// client timeout generous enough for a slow link would be uselessly long for a
	// server that accepts the connection and then says nothing.
	ctx, cancel := context.WithTimeout(context.Background(), panelURLFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return info, fmt.Errorf("that URL could not be requested: %w", err)
	}
	req.Header.Set("User-Agent", "vpn-ui")

	resp, err := panelFetchClient().Do(req)
	if err != nil {
		return info, fmt.Errorf("downloading from that URL failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("that URL answered HTTP %d, not a file", resp.StatusCode)
	}

	// A wrong link most often answers 200 with an HTML page (a login wall, a repo
	// page, a "file not found" template). StagePanelBinary's ELF check catches that,
	// but naming it here turns "not a linux binary" into something the operator can
	// act on.
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		return info, errors.New("that URL served a web page, not a binary: use the direct download link to the asset")
	}

	// Feed the overview's % bar and speed readout while the panel pulls the file. The
	// upload path measures this in the browser, which is the end that knows what it
	// has put on the wire; here the transfer happens entirely server-side, so the
	// same counters the GitHub updater publishes are what the page polls. Without
	// them a 300MB fetch is several silent minutes, which reads as a hang.
	resetUpdateCounters()
	setUpdateProgress(updatePhaseDownloading, 0)

	info, err = StagePanelBinary(
		&phaseFlipReader{r: newProgressReader(resp.Body, resp.ContentLength)},
		resp.ContentLength,
	)
	if err != nil {
		setUpdateProgress(updatePhaseError, 0)
		return info, err
	}
	// Staged, not installed: the phase belongs to the confirmation dialog now. The
	// counters are left alone so the bar keeps the size it just moved.
	setUpdateProgress(updatePhaseStaged, 100)
	return info, nil
}

// phaseFlipReader moves the published phase on from "downloading" the moment the body
// is exhausted. What follows is not instant on a file this size (an ELF check, a build
// info parse, and a -v probe that execs it), and reporting a download through all of
// that shows a bar frozen at 99% with the speed decaying to zero.
type phaseFlipReader struct {
	r      io.Reader
	flipped bool
}

func (p *phaseFlipReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if err != nil && !p.flipped {
		p.flipped = true
		setUpdateProgress(updatePhaseChecking, 99)
	}
	return n, err
}

// validatePanelBinaryURL rejects what cannot be a download before a connection is
// opened. Only http and https: the fetch below is a plain HTTP GET, and a scheme it
// cannot speak (file://, ftp://) should be refused by name rather than as a transport
// error the operator has to decode.
func validatePanelBinaryURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("enter the URL of the binary to install")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("that is not a valid URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	case "":
		raw = "https://" + raw
		u, err = url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("that is not a valid URL: %w", err)
		}
	default:
		return "", fmt.Errorf("%s:// cannot be downloaded from, use http:// or https://", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("that URL has no host")
	}
	return u.String(), nil
}

// panelFetchClient is the client StagePanelBinaryFromURL downloads with. Stall guards
// only, no overall deadline: the context carries that. Proxy settings are taken from
// the environment, which is how a panel behind one already reaches GitHub.
func panelFetchClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

// StagedPanelBinaryInfo reports what is waiting, if anything.
func StagedPanelBinaryInfo() (StagedPanelInfo, bool) {
	stagedPanelMu.Lock()
	defer stagedPanelMu.Unlock()
	return stagedPanelInfo, stagedPanelPath != ""
}

// DiscardStagedPanelBinary drops a staged upload and its file. Called when the
// operator backs out of the confirmation, and before staging a new one.
func DiscardStagedPanelBinary() {
	stagedPanelMu.Lock()
	staged := stagedPanelPath
	stagedPanelPath, stagedPanelInfo, stagedPanelAt = "", StagedPanelInfo{}, time.Time{}
	stagedPanelMu.Unlock()

	if staged != "" {
		_ = os.Remove(staged)
		return
	}
	// Nothing tracked in memory does not mean nothing on disk: a panel that restarted
	// mid-flow left its staging file behind, and it is not ours to keep.
	if exe, err := panelExecutablePath(); err == nil {
		_ = os.Remove(exe + ".upload")
	}
}

// CleanStagedPanelUpload removes a staged upload left behind by a panel that died, or
// was itself updated, between the inspect and apply steps. The token that made such a
// file installable lived only in that process's memory, so anything still on disk at
// startup is orphaned by definition, and it is the size of a whole panel binary.
// Called once at startup, next to the orphan-daemon reap.
func CleanStagedPanelUpload() {
	exe, err := panelExecutablePath()
	if err != nil {
		return
	}
	stale := exe + ".upload"
	if _, err := os.Stat(stale); err != nil {
		return
	}
	if err := os.Remove(stale); err != nil {
		logger.Warning("panel update: could not remove a stale staged upload:", err)
		return
	}
	logger.Infof("panel update: removed a stale staged upload at %s", stale)
}

// isGoBinary reports whether path carries Go build info. A pure parse with no
// execution, used as the gate in front of the -v probe.
//
// It cannot be used to READ the version: build.sh compiles `go build main.go`, a file
// argument, so the recorded main package is "command-line-arguments" with no module
// and no version, and the panel's own version is a go:embed of config/version with
// nothing around it to anchor a scan on.
func isGoBinary(path string) bool {
	_, err := buildinfo.ReadFile(path)
	return err == nil
}

// panelExecutablePath resolves the running binary through any symlink, which is the
// path the install renames over.
func panelExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot resolve own path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

// panelBinaryVersion reads a binary's version by running it with -v.
//
// It has to be exec'd rather than parsed: the version is a go:embed'd string in the
// data section, so debug/buildinfo does not carry it and a byte scan would be guessing.
// Executing an uploaded file is not a new exposure here, because the very next step is
// to install it AS the panel and exec it as root; a caller who can upload can already
// do that, and the endpoint is super-admin only. It is still bounded: a timeout, a
// capped stdout, no inherited environment, and only after the ELF check has passed.
func panelBinaryVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), panelVersionProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "-v")
	// A deliberately bare environment: the probe needs nothing from ours, and the
	// panel's own variables (VPNUI_*) should not steer a stranger's binary.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = filepath.Dir(path)
	var out cappedBuffer
	out.max = panelVersionProbeMaxOut
	cmd.Stdout = &out
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", errors.New("that binary did not answer with a version (it hung), so it is not a vpn-ui build")
		}
		return "", errors.New("that binary could not be run to read its version, so it is not a usable vpn-ui build")
	}

	// First line only. -v prints the version and exits, so anything after it is noise
	// from a binary that is not what it claims to be.
	version := strings.TrimSpace(out.buf.String())
	if i := strings.IndexAny(version, "\r\n"); i >= 0 {
		version = strings.TrimSpace(version[:i])
	}
	if !panelVersionPattern.MatchString(version) {
		return "", errors.New("that file did not report a version number, so it is not a vpn-ui binary")
	}
	return strings.TrimPrefix(version, "v"), nil
}

// comparePanelVersions classifies the staged version against the running one. Reuses
// versionNewer so "is this newer" is decided by the same rule the release check
// applies.
//
// Parseability is checked FIRST because versionNewer answers false both for "equal"
// and for "I cannot read this": without the check, an unreadable tag would compare
// equal to everything and be waved through as "same version". And equality is decided
// numerically rather than by string, so 1.8 and 1.8.0 are one version rather than an
// unknown pair the operator gets warned about for no reason.
func comparePanelVersions(staged, current string) string {
	if !parsablePanelVersion(staged) || !parsablePanelVersion(current) {
		return PanelUploadUnknown
	}
	switch {
	case versionNewer(staged, current):
		return PanelUploadUpgrade
	case versionNewer(current, staged):
		return PanelUploadDowngrade
	default:
		return PanelUploadSame
	}
}

// parsablePanelVersion reports whether versionNewer can actually order this string:
// a leading "v" and dotted decimal components, nothing else.
func parsablePanelVersion(v string) bool {
	return panelVersionPattern.MatchString(strings.TrimSpace(v))
}

// cappedBuffer collects at most max bytes and silently drops the rest, so a binary
// that floods stdout cannot make the probe allocate without bound. Writes still
// succeed past the cap: failing them would make the child die of EPIPE and turn a
// chatty binary into an unreadable error.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// humanBytes renders a size for an error message the operator reads once.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
