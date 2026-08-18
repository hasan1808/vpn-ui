package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/corebundle"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"
)

// GetBinaryName returns the Xray binary filename for the current OS and architecture.
func GetBinaryName() string {
	return fmt.Sprintf("xray-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// GetBinaryPath returns the full path to the Xray binary executable.
func GetBinaryPath() string {
	return config.GetBinFolderPath() + "/" + GetBinaryName()
}

// GetConfigPath returns the path to the Xray configuration file in the binary folder.
func GetConfigPath() string {
	return config.GetBinFolderPath() + "/config.json"
}

// GetSpeedLimitPath returns the path to the per-account speed limit sidecar file.
//
// The rates live BESIDE config.json rather than in it: they change whenever an
// account crosses its "Limit After" threshold, and anything inside the Config graph
// makes Config.Equals report a change, which restarts Xray and drops every live
// connection on the box. The patched core watches this file's mtime instead, so a
// rate change costs a reload of one small JSON document.
func GetSpeedLimitPath() string {
	return config.GetBinFolderPath() + "/speedlimits.json"
}

// GetGeositePath returns the path to the geosite data file used by Xray.
func GetGeositePath() string {
	return config.GetBinFolderPath() + "/geosite.dat"
}

// GetGeoipPath returns the path to the geoip data file used by Xray.
func GetGeoipPath() string {
	return config.GetBinFolderPath() + "/geoip.dat"
}

// GetIPLimitLogPath returns the path to the IP limit log file.
func GetIPLimitLogPath() string {
	return config.GetLogFolder() + "/3xipl.log"
}

// GetIPLimitBannedLogPath returns the path to the banned IP log file.
func GetIPLimitBannedLogPath() string {
	return config.GetLogFolder() + "/3xipl-banned.log"
}

// GetIPLimitBannedPrevLogPath returns the path to the previous banned IP log file.
func GetIPLimitBannedPrevLogPath() string {
	return config.GetLogFolder() + "/3xipl-banned.prev.log"
}

// GetAccessPersistentLogPath returns the path to the persistent access log file.
func GetAccessPersistentLogPath() string {
	return config.GetLogFolder() + "/3xipl-ap.log"
}

// GetAccessPersistentPrevLogPath returns the path to the previous persistent access log file.
func GetAccessPersistentPrevLogPath() string {
	return config.GetLogFolder() + "/3xipl-ap.prev.log"
}

// GetAccessLogPath reads the Xray config and returns the access log file path.
func GetAccessLogPath() (string, error) {
	config, err := os.ReadFile(GetConfigPath())
	if err != nil {
		logger.Warningf("Failed to read configuration file: %s", err)
		return "", err
	}

	jsonConfig := map[string]any{}
	err = json.Unmarshal([]byte(config), &jsonConfig)
	if err != nil {
		logger.Warningf("Failed to parse JSON configuration: %s", err)
		return "", err
	}

	if jsonConfig["log"] != nil {
		jsonLog := jsonConfig["log"].(map[string]any)
		if jsonLog["access"] != nil {
			accessLogPath := jsonLog["access"].(string)
			return accessLogPath, nil
		}
	}
	return "", err
}

// AccessLogEnabled reports whether Xray is configured to write an access log at all.
// "none" is Xray's own spelling of "disabled" and is the shipped default (see
// web/service/config.json), so an empty or "none" path is the answer rather than a
// failure. Anything that reads that file needs this to tell "the log is off" apart from
// "the log is on and has nothing in it yet", which it otherwise cannot.
func AccessLogEnabled() bool {
	p, err := GetAccessLogPath()
	if err != nil {
		return false
	}
	return p != "" && p != "none"
}

// stopProcess calls Stop on the given Process instance.
func stopProcess(p *Process) {
	p.Stop()
}

// Process wraps an Xray process instance and provides management methods.
type Process struct {
	*process
}

// NewProcess creates a new Xray process and sets up cleanup on garbage collection.
func NewProcess(xrayConfig *Config) *Process {
	p := &Process{newProcess(xrayConfig)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

// NewTestProcess creates a new Xray process that uses a specific config file path.
// Used for test runs (e.g. outbound test) so the main config.json is not overwritten.
// The config file at configPath is removed when the process is stopped.
func NewTestProcess(xrayConfig *Config, configPath string) *Process {
	p := &Process{newTestProcess(xrayConfig, configPath)}
	runtime.SetFinalizer(p, stopProcess)
	return p
}

type process struct {
	cmd *exec.Cmd

	version string
	apiPort int

	onlineClients []string
	// onlineMemberships is the same tick's liveness, per (inbound, account) rather
	// than per account: "<inboundId>:<email>", with inbound 0 for a session whose
	// source inbound the collector could not name. Held here beside onlineClients
	// because both are derived from one traffic tick and neither survives a restart
	// (nothing persists liveness; the next tick rebuilds it in full).
	onlineMemberships []string

	config     *Config
	configPath string // if set, use this path instead of GetConfigPath() and remove on Stop
	logWriter  *LogWriter
	exitErr    error
	startTime  time.Time
}

// newProcess creates a new internal process struct for Xray.
func newProcess(config *Config) *process {
	return &process{
		version:   "Unknown",
		config:    config,
		logWriter: NewLogWriter(),
		startTime: time.Now(),
	}
}

// newTestProcess creates a process that writes and runs with a specific config path.
func newTestProcess(config *Config, configPath string) *process {
	p := newProcess(config)
	p.configPath = configPath
	return p
}

// IsRunning returns true if the Xray process is currently running.
func (p *process) IsRunning() bool {
	if p.cmd == nil || p.cmd.Process == nil {
		return false
	}
	if p.cmd.ProcessState == nil {
		return true
	}
	return false
}

// GetErr returns the last error encountered by the Xray process.
func (p *process) GetErr() error {
	return p.exitErr
}

// GetResult returns the last log line or error from the Xray process.
func (p *process) GetResult() string {
	if len(p.logWriter.lastLine) == 0 && p.exitErr != nil {
		return p.exitErr.Error()
	}
	return p.logWriter.lastLine
}

// GetVersion returns the version string of the Xray process.
func (p *process) GetVersion() string {
	return p.version
}

// GetAPIPort returns the API port used by the Xray process.
//
// Nil-safe on purpose. The package global this is called through is nil until a
// core has been started, and of its call sites in web/service only about half
// check that first, so the rest panicked on a panel whose core never came up
// (a config the core refused, a missing binary, a port conflict). A panic there
// is not a failed request, it kills the panel process on the request goroutine.
//
// 0 is the right answer for "no API to talk to": XrayAPI.Init refuses that port
// before it dials, and the handler methods then report that they are not
// connected rather than dereferencing a client that was never built.
func (p *Process) GetAPIPort() int {
	if p == nil {
		return 0
	}
	return p.apiPort
}

// GetConfig returns the configuration used by the Xray process.
func (p *Process) GetConfig() *Config {
	return p.config
}

// GetOnlineClients returns the list of online clients for the Xray process.
func (p *Process) GetOnlineClients() []string {
	return p.onlineClients
}

// SetOnlineClients sets the list of online clients for the Xray process.
func (p *Process) SetOnlineClients(users []string) {
	p.onlineClients = users
}

// GetOnlineMemberships returns which (inbound, account) pairs the last tick saw
// traffic for, as "<inboundId>:<email>".
func (p *Process) GetOnlineMemberships() []string {
	return p.onlineMemberships
}

// SetOnlineMemberships records which (inbound, account) pairs the last tick saw
// traffic for.
func (p *Process) SetOnlineMemberships(pairs []string) {
	p.onlineMemberships = pairs
}

// GetUptime returns the uptime of the Xray process in seconds.
func (p *Process) GetUptime() uint64 {
	return uint64(time.Since(p.startTime).Seconds())
}

// refreshAPIPort updates the API port from the inbound configs.
func (p *process) refreshAPIPort() {
	for _, inbound := range p.config.InboundConfigs {
		if inbound.Tag == "api" {
			p.apiPort = inbound.Port
			break
		}
	}
}

// refreshVersion updates the version string by running the Xray binary with -version.
func (p *process) refreshVersion() {
	cmd := exec.Command(GetBinaryPath(), "-version")
	data, err := cmd.Output()
	if err != nil {
		p.version = "Unknown"
	} else {
		datas := bytes.Split(data, []byte(" "))
		if len(datas) <= 1 {
			p.version = "Unknown"
		} else {
			p.version = string(datas[1])
		}
	}
}

// Start launches the Xray process with the current configuration.
func (p *process) Start() (err error) {
	if p.IsRunning() {
		return errors.New("xray is already running")
	}

	defer func() {
		if err != nil {
			logger.Error("Failure in running xray-core process: ", err)
			p.exitErr = err
		}
	}()

	data, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return common.NewErrorf("Failed to generate XRAY configuration files: %v", err)
	}

	err = os.MkdirAll(config.GetLogFolder(), 0o770)
	if err != nil {
		logger.Warningf("Failed to create log folder: %s", err)
	}

	configPath := GetConfigPath()
	if p.configPath != "" {
		configPath = p.configPath
	}
	err = os.WriteFile(configPath, data, fs.ModePerm)
	if err != nil {
		return common.NewErrorf("Failed to write configuration file: %v", err)
	}

	// Ensure any embedded core is in place before resolving the binary path. This
		// guards against builds or deploys that skipped the main startup extraction.
		binDir := config.GetBinFolderPath()
		if corebundle.HasXray() {
			if pth, exErr := corebundle.ExtractXray(binDir); exErr != nil {
				logger.Warning("could not extract bundled xray core at Start():", exErr)
			} else if pth != "" {
				logger.Info("extracted bundled xray core to", pth)
			}
		}

		// Resolve binary path: prefer configured bin folder, but fall back to any xray on PATH.
		binPath := GetBinaryPath()
		if _, statErr := os.Stat(binPath); statErr != nil {
			// Try lookups for architecture-specific name or the generic "xray" on PATH.
			if lp, lpErr := exec.LookPath(GetBinaryName()); lpErr == nil {
				binPath = lp
			} else if lp2, lpErr2 := exec.LookPath("xray"); lpErr2 == nil {
				binPath = lp2
			} else {
				return common.NewErrorf("XRAY binary not found at %s and not available on PATH; place %s in %s or set VPNUI_BIN_FOLDER", binPath, GetBinaryName(), config.GetBinFolderPath())
			}
		}
		cmd := exec.Command(binPath, "-c", configPath)
		p.cmd = cmd

		// Hand the speed limit sidecar to the patched core out of band. An env var is used
		// rather than a config section because Xray's app configs are protobuf Any values,
		// so a plain JSON side-channel there would drag infra/conf and codegen into the
		// fork patch, and because anything in the config restarts Xray on every change.
		//
		// Resolve to an absolute path: cmd.Dir is never set, so Xray inherits whatever cwd
		// the panel was started with, and GetBinFolderPath is RELATIVE ("bin") unless
		// VPNUI_BIN_FOLDER overrides it. Resolving here pins the path to the cwd the panel
		// itself resolves "bin" against, instead of trusting Xray to resolve it the same way.
		speedLimitPath := GetSpeedLimitPath()
		if abs, absErr := filepath.Abs(speedLimitPath); absErr == nil {
			speedLimitPath = abs
		}
		cmd.Env = append(os.Environ(), "XRAY_SPEEDLIMIT_FILE="+speedLimitPath)

		cmd.Stdout = p.logWriter
		cmd.Stderr = p.logWriter

	go func() {
		err := cmd.Run()
		if err != nil {
			logger.Error("Failure in running xray-core:", err)
			p.exitErr = err
		}
	}()

	p.refreshVersion()
	p.refreshAPIPort()

	return nil
}

// Stop terminates the running Xray process.
func (p *process) Stop() error {
	if !p.IsRunning() {
		return errors.New("xray is not running")
	}

	// Remove temporary config file used for test runs so main config is never touched
	if p.configPath != "" {
		if p.configPath != GetConfigPath() {
			// Check if file exists before removing
			if _, err := os.Stat(p.configPath); err == nil {
				_ = os.Remove(p.configPath)
			}
		}
	}

	return p.cmd.Process.Signal(syscall.SIGTERM)
}

// writeCrashReport writes a crash report to the binary folder with a timestamped filename.
func writeCrashReport(m []byte) error {
	crashReportPath := config.GetBinFolderPath() + "/core_crash_" + time.Now().Format("20060102_150405") + ".log"
	return os.WriteFile(crashReportPath, m, os.ModePerm)
}
