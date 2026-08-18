package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/config"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/xray"

	"gorm.io/gorm"
)

// OutboundService provides business logic for managing Xray outbound configurations.
// It handles outbound traffic monitoring and statistics.
type OutboundService struct{}

// testSemaphore limits concurrent outbound tests to prevent resource exhaustion.
var testSemaphore sync.Mutex

func (s *OutboundService) AddTraffic(traffics []*xray.Traffic, clientTraffics []*xray.ClientTraffic) (error, bool) {
	var err error
	db := database.GetDB()
	tx := db.Begin()

	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	err = s.addOutboundTraffic(tx, traffics)
	if err != nil {
		return err, false
	}

	return nil, false
}

func (s *OutboundService) addOutboundTraffic(tx *gorm.DB, traffics []*xray.Traffic) error {
	if len(traffics) == 0 {
		return nil
	}

	var err error

	for _, traffic := range traffics {
		if traffic.IsOutbound {

			var outbound model.OutboundTraffics

			err = tx.Model(&model.OutboundTraffics{}).Where("tag = ?", traffic.Tag).
				FirstOrCreate(&outbound).Error
			if err != nil {
				return err
			}

			outbound.Tag = traffic.Tag
			outbound.Up = outbound.Up + traffic.Up
			outbound.Down = outbound.Down + traffic.Down
			outbound.Total = outbound.Up + outbound.Down

			err = tx.Save(&outbound).Error
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *OutboundService) GetOutboundsTraffic() ([]*model.OutboundTraffics, error) {
	db := database.GetDB()
	var traffics []*model.OutboundTraffics

	err := db.Model(model.OutboundTraffics{}).Find(&traffics).Error
	if err != nil {
		logger.Warning("Error retrieving OutboundTraffics: ", err)
		return nil, err
	}

	return traffics, nil
}

func (s *OutboundService) ResetOutboundTraffic(tag string) error {
	db := database.GetDB()

	whereText := "tag "
	if tag == "-alltags-" {
		whereText += " <> ?"
	} else {
		whereText += " = ?"
	}

	result := db.Model(model.OutboundTraffics{}).
		Where(whereText, tag).
		Updates(map[string]any{"up": 0, "down": 0, "total": 0})

	err := result.Error
	if err != nil {
		return err
	}

	return nil
}

// TestOutboundResult represents the result of testing an outbound
type TestOutboundResult struct {
	Success    bool   `json:"success"`
	Delay      int64  `json:"delay"` // Delay in milliseconds
	Error      string `json:"error,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	// Exit is the address the outbound actually egresses from, and its country,
	// probed THROUGH the outbound under test. Only filled on success, and only
	// best-effort: an outbound that passed the reachability test but blocks the
	// probe still reports a successful test with no exit info. A POINTER so
	// omitempty actually elides it: omitempty never elides a struct value, so a
	// failed probe would otherwise ship a bare "exit":{} to the client.
	Exit *ExitInfo `json:"exit,omitempty"`
}

// OutboundStatus captures the last test outcome for an outbound. Persisted
// server-side (keyed by outbound tag) so both the Xray page and the dashboard
// overview can render connectivity after a reload.
type OutboundStatus struct {
	Success    bool      `json:"success"`
	Delay      int64     `json:"delay"`
	StatusCode int       `json:"statusCode,omitempty"`
	Error      string    `json:"error,omitempty"`
	Exit       *ExitInfo `json:"exit,omitempty"`
	TestedAt   int64     `json:"testedAt"`
}

// OutboundStatusRow is the dashboard-facing view of one outbound: its tag and
// protocol from the current config, its accumulated traffic, and the last test
// outcome when one exists.
type OutboundStatusRow struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Up       int64           `json:"up"`
	Down     int64           `json:"down"`
	Total    int64           `json:"total"`
	Status   *OutboundStatus `json:"status,omitempty"`
}

// TestOutbound tests an outbound by creating a temporary xray instance and measuring response time.
// allOutboundsJSON must be a JSON array of all outbounds; they are copied into the test config
// and then put through the SAME synthesis the live config gets (see createTestConfig), so what
// is measured is what will run. Only the test inbound and a route rule (to the tested outbound
// tag) are added.
func (s *OutboundService) TestOutbound(outboundJSON string, testURL string, allOutboundsJSON string) (*TestOutboundResult, error) {
	if testURL == "" {
		testURL = "https://www.google.com/generate_204"
	}

	// Limit to one concurrent test at a time
	if !testSemaphore.TryLock() {
		return &TestOutboundResult{
			Success: false,
			Error:   "Another outbound test is already running, please wait",
		}, nil
	}
	defer testSemaphore.Unlock()

	// Parse the outbound being tested to get its tag
	var testOutbound map[string]any
	if err := json.Unmarshal([]byte(outboundJSON), &testOutbound); err != nil {
		return &TestOutboundResult{
			Success: false,
			Error:   fmt.Sprintf("Invalid outbound JSON: %v", err),
		}, nil
	}
	outboundTag, _ := testOutbound["tag"].(string)
	if outboundTag == "" {
		return &TestOutboundResult{
			Success: false,
			Error:   "Outbound has no tag",
		}, nil
	}
	if protocol, _ := testOutbound["protocol"].(string); protocol == "blackhole" || outboundTag == "blocked" {
		return &TestOutboundResult{
			Success: false,
			Error:   "Blocked/blackhole outbound cannot be tested",
		}, nil
	}

	// Use all outbounds when provided; otherwise fall back to single outbound
	var allOutbounds []any
	if allOutboundsJSON != "" {
		if err := json.Unmarshal([]byte(allOutboundsJSON), &allOutbounds); err != nil {
			return &TestOutboundResult{
				Success: false,
				Error:   fmt.Sprintf("Invalid allOutbounds JSON: %v", err),
			}, nil
		}
	}
	if len(allOutbounds) == 0 {
		allOutbounds = []any{testOutbound}
	}

	// Read the stored tunnels ONCE, so the refusal below and the synthesis inside
	// createTestConfig cannot disagree about a tunnel that changed in between.
	tunnels := (&VpnOutboundService{}).List()
	sshTunnels := (&SshOutboundService{}).List()

	// A tunnel with no live device is refused here rather than tested. The synthesis
	// turns that tag into a BLACKHOLE (applyVpnOutboundsWith fails closed), so the test
	// would otherwise report "Request failed" and leave the operator guessing between a
	// dead tunnel, a dead proxy and a dead internet. Naming the tunnel is the whole
	// value: this is the one failure the test can diagnose exactly.
	if t, ok := findVpnTunnel(tunnels, outboundTag); ok {
		if why := vpnOutNotTestable(t); why != "" {
			return &TestOutboundResult{Success: false, Error: why}, nil
		}
	}

	// Find an available port for test inbound
	testPort, err := findAvailablePort()
	if err != nil {
		return &TestOutboundResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to find available port: %v", err),
		}, nil
	}

	// Copy all outbounds, synthesize the tunnels over them, add test inbound and route rule
	testConfig := s.createTestConfig(outboundTag, allOutbounds, testPort, tunnels, sshTunnels)

	// Use a temporary config file so the main config.json is never overwritten
	testConfigPath, err := createTestConfigPath()
	if err != nil {
		return &TestOutboundResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to create test config path: %v", err),
		}, nil
	}
	defer os.Remove(testConfigPath) // ensure temp file is removed even if process is not stopped

	// Create temporary xray process with its own config file
	testProcess := xray.NewTestProcess(testConfig, testConfigPath)
	defer func() {
		if testProcess.IsRunning() {
			testProcess.Stop()
		}
	}()

	// Start the test process
	if err := testProcess.Start(); err != nil {
		return &TestOutboundResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to start test xray instance: %v", err),
		}, nil
	}

	// Wait for xray to start listening on the test port
	if err := waitForPort(testPort, 3*time.Second); err != nil {
		if !testProcess.IsRunning() {
			result := testProcess.GetResult()
			return &TestOutboundResult{
				Success: false,
				Error:   fmt.Sprintf("Xray process exited: %s", result),
			}, nil
		}
		return &TestOutboundResult{
			Success: false,
			Error:   fmt.Sprintf("Xray failed to start listening: %v", err),
		}, nil
	}

	// Check if process is still running
	if !testProcess.IsRunning() {
		result := testProcess.GetResult()
		return &TestOutboundResult{
			Success: false,
			Error:   fmt.Sprintf("Xray process exited: %s", result),
		}, nil
	}

	// Test the connection through proxy
	delay, statusCode, err := s.testConnection(testPort, testURL)
	if err != nil {
		return &TestOutboundResult{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// The test proved the outbound works; now ask what the far side looks like.
	// Done only on success, and only after the delay measurement, so the extra
	// round trips cannot inflate the reported latency.
	return &TestOutboundResult{
		Success:    true,
		Delay:      delay,
		StatusCode: statusCode,
		Exit:       exitOrNil(s.probeExit(testPort)),
	}, nil
}

// exitOrNil drops an exit probe that learned nothing, so the field is absent
// from the response rather than present and blank.
func exitOrNil(e ExitInfo) *ExitInfo {
	if e.Empty() {
		return nil
	}
	return &e
}

// probeExit asks, through the outbound's own SOCKS proxy, which address the
// internet sees and where it is. Best-effort: the outbound has already passed
// its test by this point, so a probe that is blocked, slow or unreachable
// returns an empty ExitInfo rather than failing the test the operator ran.
func (s *OutboundService) probeExit(proxyPort int) ExitInfo {
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", proxyPort))
	if err != nil {
		return ExitInfo{}
	}
	client := &http.Client{
		// Deliberately tighter than the reachability test's 10s: this is
		// decoration, and the operator is watching a spinner while it runs.
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			Proxy:              http.ProxyURL(proxyURL),
			DialContext:        (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
			MaxIdleConns:       1,
			IdleConnTimeout:    5 * time.Second,
			DisableCompression: true,
		},
	}
	defer client.CloseIdleConnections()
	return LookupExit(client)
}

// createTestConfig creates a test config by copying all outbounds, running the stored VPN
// tunnels over them exactly as the live config build does, and adding only the test inbound
// (SOCKS) and a route rule that sends traffic to the given outbound tag.
//
// THE SYNTHESIS IS NOT OPTIONAL, and leaving it out is what this comment is for. A VPN
// tunnel's row in the template is NOT the outbound Xray runs: applyVpnOutboundsWith rebuilds
// it on every config build, forcing the freedom protocol, the UseIP strategy and the
// SO_BINDTODEVICE pin, dropping mux and dropping sockopt.dialerProxy. Copying the row
// verbatim therefore tested a DIFFERENT outbound from the one in service, and every way it
// could differ was a way the test could lie:
//
//   - a dialerProxy the operator typed into the sockopt form is deleted from the live
//     outbound and was kept by the test. dialerProxy CANCELS the interface pin (DialSystem
//     returns redirect() before the bind ever happens), so the test dialled the proxy and
//     reported the PROXY's exit address for a tunnel that egresses somewhere else entirely.
//     Measured on this box: pin only -> 65.109.217.240 (FI, the tunnel); pin + dialerProxy
//     -> 212.8.240.13 (NL, the proxy). That is the report this function exists to answer.
//   - the pin in the row is a COPY, written when the tunnel was created. A tunnel that
//     redialled onto another device leaves it stale, and a stale pin does not fail: the core
//     swallows the failed BindToDevice at Info level and the socket goes out the host's own
//     WAN. Measured: pin to a device that does not exist -> 216.147.121.163 (the host).
//   - a tunnel that is down is a blackhole in the live config and was a plain freedom
//     outbound in the test, i.e. the test leaked out the host WAN and called it a pass.
//
// The last two matter most, because they are silent: a green delay tag and an exit address
// that is not the tunnel's is the exact tool an operator uses to confirm there is NO leak.
// Both tunnel lists are ARGUMENTS rather than read here, so this stays a pure function of
// what it is given and the tests can pin its behaviour without a database.
func (s *OutboundService) createTestConfig(outboundTag string, allOutbounds []any, testPort int,
	tunnels []VpnOutboundConfig, sshTunnels []SshOutboundConfig) *xray.Config {
	// Test inbound (SOCKS proxy) - only addition to inbounds
	testInbound := xray.InboundConfig{
		Tag:      "test-inbound",
		Listen:   json_util.RawMessage(`"127.0.0.1"`),
		Port:     testPort,
		Protocol: "socks",
		Settings: json_util.RawMessage(`{"auth":"noauth","udp":true}`),
	}

	// Outbounds: copy all, but set noKernelTun=true for WireGuard outbounds
	processedOutbounds := make([]any, len(allOutbounds))
	for i, ob := range allOutbounds {
		outbound, ok := ob.(map[string]any)
		if !ok {
			processedOutbounds[i] = ob
			continue
		}
		if protocol, ok := outbound["protocol"].(string); ok && protocol == "wireguard" {
			// Set noKernelTun to true for WireGuard outbounds
			if settings, ok := outbound["settings"].(map[string]any); ok {
				settings["noKernelTun"] = true
			} else {
				// Create settings if it doesn't exist
				outbound["settings"] = map[string]any{
					"noKernelTun": true,
				}
			}
		}
		processedOutbounds[i] = outbound
	}
	outboundsJSON, _ := json.Marshal(processedOutbounds)

	// Create routing rule to route all traffic through test outbound
	routingRules := []map[string]any{
		{
			"type":        "field",
			"outboundTag": outboundTag,
			"network":     "tcp,udp",
		},
	}

	routingJSON, _ := json.Marshal(map[string]any{
		"domainStrategy": "AsIs",
		"rules":          routingRules,
	})

	// Disable logging for test process to avoid creating orphaned log files
	logConfig := map[string]any{
		"loglevel": "warning",
		"access":   "none",
		"error":    "none",
		"dnsLog":   false,
	}
	logJSON, _ := json.Marshal(logConfig)

	// Create minimal config
	cfg := &xray.Config{
		LogConfig: json_util.RawMessage(logJSON),
		InboundConfigs: []xray.InboundConfig{
			testInbound,
		},
		OutboundConfigs: json_util.RawMessage(string(outboundsJSON)),
		RouterConfig:    json_util.RawMessage(string(routingJSON)),
		Policy:          json_util.RawMessage(`{}`),
		Stats:           json_util.RawMessage(`{}`),
	}

	// The same two calls the live build makes, in the same order and on the same lists,
	// so the two cannot drift: a change to either synthesis reaches the test
	// automatically. A tunnel that has no row here is APPENDED, which is also what the
	// live build does and is what makes a tunnel testable at all before the operator has
	// pressed Save on the Xray page.
	//
	// SSH is included for the same reason as VPN, in its smaller form: the row is a socks
	// outbound aimed at a loopback port the panel allocated, and the port in the row is a
	// copy. A tunnel that came back on a different port after a restart leaves the row
	// pointing at whatever else took the number, and that is not a connection error, it is
	// a successful test of somebody else's proxy.
	if err := applySshOutboundsWith(cfg, sshTunnels); err != nil {
		logger.Warning("outbound test: could not synthesize the SSH outbounds:", err)
	}
	if err := applyVpnOutboundsWith(cfg, tunnels); err != nil {
		logger.Warning("outbound test: could not synthesize the VPN client outbounds:", err)
	}

	return cfg
}

// vpnOutNotTestable says why a stored tunnel cannot be tested, or "" when it can.
//
// The three conditions are applyVpnOutboundsWith's own fail-closed test, deliberately
// duplicated rather than inferred from the config it produces: reading a blackhole back out
// of the marshalled outbounds would say WHAT happened and not WHY, and "enabled but the
// device is gone" and "switched off" want different sentences.
func vpnOutNotTestable(t VpnOutboundConfig) string {
	switch {
	case !t.Enable:
		return fmt.Sprintf("the %q tunnel is switched off, so there is nothing to test. "+
			"The live config blackholes this tag while it is off, which is why the test refuses "+
			"rather than measuring the host's own connection and calling it a pass", t.Tag)
	case t.Iface == "":
		return fmt.Sprintf("the %q tunnel has no network device, so it never came up. "+
			"Re-save the outbound to dial it again, and read the client log if it still fails", t.Tag)
	case vpnOutIfaceGone(t.Iface):
		return fmt.Sprintf("the %q tunnel claims device %q, which is not on this host: the tunnel "+
			"is down. Traffic on this tag is blackholed until it comes back, which is deliberate - "+
			"an outbound pinned to a device that is gone does NOT fail, it silently leaves through "+
			"the host's own WAN", t.Tag, t.Iface)
	}
	return ""
}

// testConnection tests the connection through the proxy and measures delay.
// It performs a warmup request first to establish the SOCKS connection and populate DNS caches,
// then measures the second request for a more accurate latency reading.
func (s *OutboundService) testConnection(proxyPort int, testURL string) (int64, int, error) {
	// Create SOCKS5 proxy URL
	proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", proxyPort)

	// Parse proxy URL
	proxyURLParsed, err := url.Parse(proxyURL)
	if err != nil {
		return 0, 0, common.NewErrorf("Invalid proxy URL: %v", err)
	}

	// Create HTTP client with proxy and keep-alive for connection reuse
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURLParsed),
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:       1,
			IdleConnTimeout:    10 * time.Second,
			DisableCompression: true,
		},
	}

	// Warmup request: establishes SOCKS/TLS connection, DNS, and TCP to the target.
	// This mirrors real-world usage where connections are reused.
	warmupResp, err := client.Get(testURL)
	if err != nil {
		return 0, 0, common.NewErrorf("Request failed: %v", err)
	}
	io.Copy(io.Discard, warmupResp.Body)
	warmupResp.Body.Close()

	// Measure the actual request on the warm connection
	startTime := time.Now()
	resp, err := client.Get(testURL)
	delay := time.Since(startTime).Milliseconds()

	if err != nil {
		return 0, 0, common.NewErrorf("Request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return delay, resp.StatusCode, nil
}

// waitForPort polls until the given TCP port is accepting connections or the timeout expires.
func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready after %v", port, timeout)
}

// findAvailablePort finds an available port for testing
func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// createTestConfigPath returns a unique path for a temporary xray config file in the bin folder.
// The temp file is created and closed so the path is reserved; Start() will overwrite it.
func createTestConfigPath() (string, error) {
	tmpFile, err := os.CreateTemp(config.GetBinFolderPath(), "xray_test_*.json")
	if err != nil {
		return "", err
	}
	path := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}
