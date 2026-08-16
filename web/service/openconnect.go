package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/xray"
)

// OcservService manages OpenConnect (ocserv) server configuration: TLS certs,
// the ocserv.conf + radcli client config, the daemon child process, and routing.
//
// Architecturally ocserv is the closest sibling of OpenVPN — a userspace tun
// daemon whose clients get a source IP inside a per-inbound /24, which the shared
// nftables TPROXY path redirects into Xray. It differs in two ways that make it
// simpler here: a SINGLE listener carries both TLS (TCP) and DTLS (UDP) on one
// port (no udp/tcp split, no 10.3 mirror), and it speaks RADIUS natively via
// radcli — so authentication, per-account IP pinning (Framed-IP-Address), and
// accounting all go through the panel's in-process RADIUS server with no
// per-connection hook scripts (unlike OpenVPN).
type OcservService struct {
	inboundService InboundService
	nftService     NftService
	radiusService  *RadiusService
	radiusSecret   string
}

// ocservSettings is the OpenConnect-specific slice of an inbound's Settings JSON.
type ocservSettings struct {
	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
	Mtu  int    `json:"mtu"`

	// TLS follows the Xray inbound model: either operator-supplied paths
	// (TlsUseFile) or inline PEM content. "Generate Self-Signed Cert" fills the
	// content fields; "Set Default Cert" copies the panel's own webCertFile/
	// webKeyFile paths (TlsUseFile mode). ocserv reads whichever is active from
	// disk, exactly like the panel's own HTTPS listener does.
	TlsUseFile      bool   `json:"tlsUseFile"`
	CertificateFile string `json:"certificateFile"` // path mode: server cert path
	KeyFile         string `json:"keyFile"`         // path mode: server key path
	Certificate     string `json:"certificate"`     // content mode: server cert PEM
	Key             string `json:"key"`             // content mode: server key PEM
	CaCert          string `json:"caCert"`          // optional CA PEM (self-signed)

	ClientToClient    bool           `json:"clientToClient"`
	CrossInbound      bool           `json:"crossInbound"`
	UserLimit         *int           `json:"userLimit"`         // nil=absent(legacy=>1); 0=no limit; else 1..64. Parse-only — enforce via effectiveUserLimit.
	UserLimitStrategy string         `json:"userLimitStrategy"` // "accept" (evict oldest) or "reject"
	IpRanges          []string       `json:"ipRanges"`          // panel-managed 10.4.x /24 ranges
	Clients           []ocservClient `json:"clients"`
}

// effectiveRanges returns the inbound's client /24 ranges, or nil to signal the
// legacy id-derived /24 (10.4.{id}).
func (o *ocservSettings) effectiveRanges() []string { return o.IpRanges }

type ocservClient struct {
	ID       string `json:"id"`       // OpenConnect username
	Password string `json:"password"` // OpenConnect password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius wires the shared RADIUS service + secret for OpenConnect auth/acct.
func (s *OcservService) SetRadius(rs *RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

// getRadiusSecret returns the RADIUS shared secret, falling back to the DB setting
// when the in-memory field is empty. Critical: the controller holds its OWN
// zero-value OcservService (SetRadius is only called on the web server's copy), so
// onOcservChanged → writeRadiusClientConfig runs with radiusSecret == "". Without
// this fallback the servers file is written as "127.0.0.1\t" (no secret), radcli
// then can't match the server ("couldn't find RADIUS server 127.0.0.1") and every
// OpenConnect auth fails. Mirrors L2tpService.getRadiusSecret.
func (s *OcservService) getRadiusSecret() string {
	if s.radiusSecret != "" {
		return s.radiusSecret
	}
	var settingService SettingService
	secret, _ := settingService.GetRadiusSecret()
	return secret
}

func (s *OcservService) GetOcservInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "openconnect").Find(&inbounds).Error
	return inbounds, err
}

func (s *OcservService) parseSettings(inbound *model.Inbound) (*ocservSettings, error) {
	settings := &ocservSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// configDir returns the directory holding an OpenConnect inbound's config, radcli,
// and (content-mode) cert files.
func (s *OcservService) configDir(inboundId int) string {
	return fmt.Sprintf("/etc/ocserv/server-%d", inboundId)
}

// ocservBinaryPath returns the ocserv executable the panel runs: the bundled
// static daemon if extracted, else a distro ocserv from PATH.
func (s *OcservService) ocservBinaryPath() string {
	return daemonBin("ocserv")
}

// occtlBinaryPath returns the occtl control tool (bundled alongside ocserv), used
// for programmatic session control (User Limit eviction in Phase 3).
func (s *OcservService) occtlBinaryPath() string {
	return daemonBin("occtl")
}

// ocservBlockFor returns the network address and prefix length of an inbound's
// client block (10.4.x), derived from its stored ranges. The server takes .1;
// clients start at .2. Defaults to the legacy 10.4.{id}.0/24 when no ranges are
// stored.
func ocservBlockFor(inbound *model.Inbound, settings *ocservSettings) (net.IP, int) {
	return vpnBlock(settings.effectiveRanges(), protocolBase("openconnect"), inbound.Id)
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port for the inbound.
// Inbound IDs are globally unique, so this shares the 12300+id formula with
// L2TP/PPTP/OpenVPN without colliding.
func (s *OcservService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound that captures the
// TPROXY-redirected OpenConnect traffic and feeds it into Xray's routing — the
// same mechanism L2TP/PPTP/OpenVPN use.
func (s *OcservService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
	port := s.GetTproxyPort(inbound)
	settings := `{"network":"tcp,udp","followRedirect":true}`
	streamSettings := `{"sockopt":{"tproxy":"tproxy","mark":255}}`
	sniffing := `{"enabled":true,"destOverride":["http","tls"]}`

	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(`"0.0.0.0"`),
		Port:           port,
		Protocol:       "dokodemo-door",
		Settings:       json_util.RawMessage(settings),
		StreamSettings: json_util.RawMessage(streamSettings),
		Tag:            inbound.Tag,
		Sniffing:       json_util.RawMessage(sniffing),
	}
}

// InitOcserv initializes OpenConnect services on panel startup.
func (s *OcservService) InitOcserv() {
	inbounds, err := s.GetOcservInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}

	logger.Info("OpenConnect: initializing services for", len(inbounds), "inbound(s)")

	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("OpenConnect: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		logger.Warning("OpenConnect: failed to setup routing:", err)
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("OpenConnect: failed to restart services:", err)
	}
}

// GenerateAllConfigs regenerates every OpenConnect config file from DB state.
func (s *OcservService) GenerateAllConfigs() error {
	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return err
	}
	if len(inbounds) == 0 {
		return nil
	}

	for _, inbound := range inbounds {
		if err := s.generateServerConfig(inbound); err != nil {
			logger.Warning("OpenConnect: skipping inbound", inbound.Id, err)
			continue
		}
		if err := s.writeCertFiles(inbound); err != nil {
			logger.Warning("OpenConnect: cert write failed for inbound", inbound.Id, err)
		}
		if err := s.writeRadiusClientConfig(inbound); err != nil {
			logger.Warning("OpenConnect: radcli config write failed for inbound", inbound.Id, err)
		}
	}
	return nil
}

// generateServerConfig writes the ocserv.conf for one inbound.
func (s *OcservService) generateServerConfig(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}

	dir := s.configDir(inbound.Id)
	os.MkdirAll(dir, 0755)
	os.MkdirAll("/var/run/ocserv", 0755)

	conf := s.buildServerConfig(inbound, settings)
	return s.writeFile(fmt.Sprintf("%s/ocserv.conf", dir), conf)
}

// ocservProcName returns the process-manager key for an OpenConnect inbound.
func ocservProcName(inboundId int) string {
	return fmt.Sprintf("ocserv-server-%d", inboundId)
}

// certPaths returns the server cert + key file paths ocserv should reference. In
// path mode the operator's own paths are used verbatim; in content mode the PEMs
// are written into the inbound's config dir (see writeCertFiles).
func (s *OcservService) certPaths(inbound *model.Inbound, settings *ocservSettings) (certPath, keyPath string) {
	if settings.TlsUseFile && strings.TrimSpace(settings.CertificateFile) != "" && strings.TrimSpace(settings.KeyFile) != "" {
		return strings.TrimSpace(settings.CertificateFile), strings.TrimSpace(settings.KeyFile)
	}
	dir := s.configDir(inbound.Id)
	return dir + "/server.crt", dir + "/server.key"
}

// hasUsableCert reports whether a server cert+key is available on disk (content
// mode written, or an operator path that exists). ocserv refuses to start without
// one, so RestartServices skips inbounds that have none yet.
func (s *OcservService) hasUsableCert(inbound *model.Inbound, settings *ocservSettings) bool {
	certPath, keyPath := s.certPaths(inbound, settings)
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	return true
}

// buildServerConfig returns the ocserv.conf content for an inbound.
func (s *OcservService) buildServerConfig(inbound *model.Inbound, settings *ocservSettings) string {
	id := inbound.Id
	dir := s.configDir(id)
	port := inbound.Port

	netAddr, prefix := ocservBlockFor(inbound, settings)
	network := netAddr.String()
	netmask := prefixToMask(prefix)

	dns1 := settings.Dns1
	if dns1 == "" {
		dns1 = "8.8.8.8"
	}
	dns2 := settings.Dns2
	if dns2 == "" {
		dns2 = "8.8.4.4"
	}
	mtu := settings.Mtu
	if mtu == 0 {
		mtu = 1420 // conservative default; DTLS/TLS overhead on a 1500 path
	}

	certPath, keyPath := s.certPaths(inbound, settings)

	var b strings.Builder
	b.WriteString("# Auto-generated by pro-ui OpenConnect service — do not edit\n")
	// groupconfig=true makes ocserv APPLY the RADIUS reply attributes to the
	// session — critically Framed-IP-Address, which pins each device to its
	// panel-assigned block IP. Verified: WITHOUT it ocserv ignores Framed-IP and
	// hands out an ipv4-network pool IP instead, so the RADIUS-tracked IP no longer
	// matches the real tunnel IP and per-device User-Limit accept-eviction (occtl
	// disconnect-by-IP) can't find the session, plus source-IP routing for the
	// device breaks. (The "401" that once prompted disabling this was an empty
	// RADIUS shared secret, not groupconfig.)
	b.WriteString(fmt.Sprintf("auth = \"radius[config=%s/radiusclient.conf,groupconfig=true]\"\n", dir))
	b.WriteString(fmt.Sprintf("acct = \"radius[config=%s/radiusclient.conf]\"\n", dir))
	b.WriteString(fmt.Sprintf("tcp-port = %d\n", port))
	b.WriteString(fmt.Sprintf("udp-port = %d\n", port))
	b.WriteString(fmt.Sprintf("socket-file = /var/run/ocserv/ocserv-%d.sock\n", id))
	// occtl control socket — used for programmatic session control (User Limit
	// eviction via `occtl -s <sock> disconnect`).
	b.WriteString("use-occtl = true\n")
	b.WriteString(fmt.Sprintf("occtl-socket-file = %s\n", s.occtlSocket(id)))
	b.WriteString("run-as-user = root\n")
	b.WriteString("run-as-group = root\n")
	b.WriteString(fmt.Sprintf("server-cert = %s\n", certPath))
	b.WriteString(fmt.Sprintf("server-key = %s\n", keyPath))
	// Widen TLS to reach old clients: allow TLS 1.0 through 1.3. NORMAL already
	// covers TLS 1.2/1.3 + DTLS (kept intact for UDP); we add TLS 1.0/1.1 back and
	// %COMPAT for legacy interop. An explicit priority string is honored directly by
	// the statically-bundled GnuTLS, so no host crypto policy can veto old TLS.
	b.WriteString("tls-priorities = \"NORMAL:%SERVER_PRECEDENCE:%COMPAT:+VERS-TLS1.0:+VERS-TLS1.1\"\n")
	if strings.TrimSpace(settings.CaCert) != "" && !settings.TlsUseFile {
		b.WriteString(fmt.Sprintf("ca-cert = %s/ca.crt\n", dir))
	}
	// We build ocserv --disable-seccomp, so the isolate-workers syscall sandbox is
	// unavailable; disabling it explicitly avoids a startup error.
	b.WriteString("isolate-workers = false\n")
	b.WriteString("max-clients = 1024\n")
	// max-same-clients = 0 (unlimited) on purpose: the User Limit K is enforced
	// server-side by the panel's RADIUS server, which pins each device to a distinct
	// block IP (Framed-IP-Address) and applies the reject/accept-evict strategy. A
	// native ocserv cap here would refuse the (K+1)-th device BEFORE RADIUS runs,
	// breaking both the reject logging and the accept-then-evict-oldest flow.
	b.WriteString("max-same-clients = 0\n")
	// Keepalive and DPD are what hold the tunnel open through NAT, and ocserv's own
	// sample values (keepalive 32400, dpd 90, mobile-dpd 1800) cannot do it here.
	//
	// keepalive is not a server timer: it is advertised as X-CSTP-Keepalive /
	// X-DTLS-Keepalive and tells the CLIENT how often to send a packet on an idle
	// tunnel. At 32400 (9 hours) an idle client sends nothing at all, so the only
	// traffic keeping the NAT mapping alive is DPD. Worse, ocserv REPLACES dpd with
	// mobile-dpd for any client whose platform header says android or apple-ios
	// (worker-vpn.c: `if (req->is_mobile) ws->user_config->dpd = mobile_dpd`), which is
	// every phone. So a phone was told "DPD every 30 minutes, keepalive every 9 hours"
	// while carrier-grade NAT drops an idle UDP mapping in well under two minutes: after
	// a few idle minutes the path is dead in the server->client direction, the client
	// has no probe due for half an hour to notice, and ocserv only tears the session down
	// after DPD_MAX_TRIES (3) x dpd, i.e. 90 minutes. Both ends believe they are
	// connected, nothing passes, and only a manual client reconnect fixes it.
	//
	// 30s keepalive is the interval every other tunnel protocol here already relies on
	// (WireGuard persistent-keepalive is 25s, IPsec NAT-T ~20s) and it refreshes both the
	// TCP and the DTLS mapping. With that in place DPD only has to answer "is this peer
	// gone", so 60s (probe at 2x, teardown at 3x = 3 minutes) is a genuinely dead link,
	// and a phone's 300s keeps the battery cost near zero while still freeing its
	// User-Limit slot in 15 minutes instead of 90.
	b.WriteString("keepalive = 30\n")
	b.WriteString("dpd = 60\n")
	b.WriteString("mobile-dpd = 300\n")
	b.WriteString("switch-to-tcp-timeout = 25\n")
	b.WriteString("try-mtu-discovery = true\n")
	b.WriteString("cisco-client-compat = true\n")
	b.WriteString("dtls-legacy = true\n")
	b.WriteString("compression = false\n")
	// Auth backend returns the tunnel IP (Framed-IP-Address); no predictable/local
	// pool assignment so the RADIUS pin is authoritative.
	b.WriteString("predictable-ips = false\n")
	b.WriteString(fmt.Sprintf("device = ocserv-%d\n", id))
	b.WriteString(fmt.Sprintf("ipv4-network = %s\n", network))
	b.WriteString(fmt.Sprintf("ipv4-netmask = %s\n", netmask))
	b.WriteString("tunnel-all-dns = true\n")
	b.WriteString(fmt.Sprintf("dns = %s\n", dns1))
	b.WriteString(fmt.Sprintf("dns = %s\n", dns2))
	b.WriteString(fmt.Sprintf("mtu = %d\n", mtu))
	// Full-tunnel: push the default route so ALL client traffic enters the tun,
	// where the nftables TPROXY hook redirects it into Xray (no split routes, no
	// masquerade — Xray owns egress).
	b.WriteString("route = default\n")
	if settings.ClientToClient {
		// Let ocserv bridge client-to-client traffic internally instead of routing
		// it out the tun (where TPROXY would capture it).
		b.WriteString("# client-to-client enabled\n")
	}
	b.WriteString("cert-user-oid = 0.9.2342.19200300.100.1.1\n")
	// log-level 3: surface per-connection auth results (sec-mod / radcli / worker
	// "failed authentication") in the daemon log without the full TLS packet dumps
	// of higher levels — so an auth failure is diagnosable from the captured log.
	b.WriteString("log-level = 3\n")

	return b.String()
}

// writeCertFiles writes the content-mode server cert/key (and optional CA) to the
// inbound's config dir. In path mode ocserv reads the operator's own files, so
// nothing is written here.
func (s *OcservService) writeCertFiles(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}
	if settings.TlsUseFile {
		return nil
	}

	dir := s.configDir(inbound.Id)
	os.MkdirAll(dir, 0755)

	if strings.TrimSpace(settings.Certificate) != "" {
		if err := s.writeFile(dir+"/server.crt", settings.Certificate); err != nil {
			return err
		}
	}
	if strings.TrimSpace(settings.Key) != "" {
		if err := s.writeFileMode(dir+"/server.key", settings.Key, 0600); err != nil {
			return err
		}
	}
	if strings.TrimSpace(settings.CaCert) != "" {
		if err := s.writeFile(dir+"/ca.crt", settings.CaCert); err != nil {
			return err
		}
	}
	return nil
}

// writeRadiusClientConfig writes the per-inbound radcli client config so ocserv
// authenticates + accounts against the panel's in-process RADIUS server. radcli
// (ocserv's RADIUS library) uses `nas-identifier` (hyphen) — distinct from pppd's
// `nas_identifier` — so it can't share L2TP/PPTP's config; it carries a per-inbound
// nas-identifier `openconnect-{id}` that the RADIUS server resolves directly.
func (s *OcservService) writeRadiusClientConfig(inbound *model.Inbound) error {
	dir := s.configDir(inbound.Id)
	os.MkdirAll(dir, 0755)

	// Reuse the self-contained dictionary the RADIUS service ships (it already
	// carries NAS-Identifier, Framed-IP-Address, and the accounting attributes).
	if err := generateRadiusDictionary(dir); err != nil {
		return fmt.Errorf("failed to write dictionary: %w", err)
	}

	config := fmt.Sprintf(`# Auto-generated by pro-ui OpenConnect (radcli) — do not edit
authserver	127.0.0.1:1812
acctserver	127.0.0.1:1813
servers		%s/servers
dictionary	%s/dictionary
default_realm
radius_timeout	5
radius_retries	3
nas-identifier	openconnect-%d
bindaddr	*
`, dir, dir, inbound.Id)
	if err := os.WriteFile(dir+"/radiusclient.conf", []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write radiusclient.conf: %w", err)
	}

	servers := fmt.Sprintf("127.0.0.1\t%s\n", s.getRadiusSecret())
	return os.WriteFile(dir+"/servers", []byte(servers), 0600)
}

// SetupRouting prepares the host so OpenConnect client traffic is TPROXY-redirected
// into Xray instead of NAT'd to the internet. Shares the fwmark policy route and
// nftables regeneration with the other VPN protocols.
func (s *OcservService) SetupRouting() error {
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	s.runCmd("modprobe", "tun")
	s.runCmd("modprobe", "nf_tproxy_ipv4")

	output, _ := exec.Command("ip", "rule", "show").Output()
	if !strings.Contains(string(output), "fwmark 0x1 lookup 100") {
		s.runCmd("ip", "rule", "add", "fwmark", "1", "lookup", "100")
	}
	s.runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100")

	return s.nftService.ApplyNftRules()
}

// RestartServices launches (or stops) an ocserv child process per inbound. An
// inbound with no usable server cert yet is skipped (ocserv refuses to start
// without one). Managed ocserv processes with no corresponding enabled inbound
// are stopped.
func (s *OcservService) RestartServices() error {
	migrateFromSystemd()

	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return err
	}

	bin := s.ocservBinaryPath()
	desired := map[string]bool{}

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("OpenConnect: skipping inbound", inbound.Id, err)
			continue
		}
		if !s.hasUsableCert(inbound, settings) {
			logger.Warning("OpenConnect: inbound", inbound.Id, "has no TLS cert yet — generate a self-signed cert or set a cert path")
			continue
		}
		dir := s.configDir(inbound.Id)
		name := ocservProcName(inbound.Id)
		desired[name] = true
		confPath := fmt.Sprintf("%s/ocserv.conf", dir)
		args := []string{"-f", "-c", confPath}
		if err := procMgr.Start(name, bin, args, nil, dir); err != nil {
			logger.Warning("OpenConnect: failed to start", name, err)
		}
	}

	for _, name := range procMgr.namesWithPrefix("ocserv-server-") {
		if !desired[name] {
			_ = procMgr.Stop(name)
		}
	}
	return nil
}

// StopServices stops all OpenConnect child processes.
func (s *OcservService) StopServices() {
	procMgr.StopByPrefix("ocserv-server-")
}

// GenerateSelfSignedCert generates a self-signed server certificate + key for
// ocserv. Unlike OpenVPN (which needs a CA + tls-crypt), ocserv only needs a
// server cert the client trusts (or bypasses with --no-cert-check); a single
// self-issued ECDSA P-384 cert suffices. Returns PEM strings: serverCert, serverKey.
//
// serverAddr is the address clients will dial; empty means the address this host
// egresses with. It becomes the CN and the SANs, which is not decoration: a
// certificate with NO subjectAltName cannot be verified by name by anything, so
// every client had to be told to skip the check. This used to mint a fixed CN of
// "pro-ui OpenConnect Server" and no SAN at all, which meant AnyConnect, the
// openconnect CLI and this panel's own OpenConnect OUTBOUND all failed
// verification against a gateway whose certificate the operator had handed them,
// with nothing wrong on either side but the certificate itself. The IKEv2
// generator has always done this (Ikev2Service.GenerateSelfSignedCert); these two
// were the odd ones out.
func (s *OcservService) GenerateSelfSignedCert(serverAddr string) (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate server key: %w", err)
	}

	host := strings.TrimSpace(serverAddr)
	if host == "" {
		host = s.getServerIP()
	}
	cn := host
	if cn == "" {
		// Nothing to name it after. Keep the old CN rather than inventing one, so a
		// host whose address cannot be detected produces exactly what it used to.
		cn = "pro-ui OpenConnect Server"
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"pro-ui"},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if host != "" {
		// Both forms, for the same reason the IKEv2 leaf carries both: an address is
		// an iPAddress SAN to a correct client and a dNSName to several real ones.
		template.DNSNames = []string{host}
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = []net.IP{ip}
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("failed to create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM), nil
}

// occtlSocket returns the occtl control-socket path for an inbound's ocserv.
func (s *OcservService) occtlSocket(inboundId int) string {
	return fmt.Sprintf("/var/run/ocserv/occtl-%d.sock", inboundId)
}

// killOcservByIP force-disconnects the ocserv session holding tunnel IP `ip` on the
// given inbound, via occtl. It is the OpenConnect analogue of killPPPByIP (used by
// the User-Limit "accept" eviction in radius.go): occtl has no disconnect-by-IP, so
// it lists sessions (`show users -j`), finds the one whose assigned IPv4 matches,
// and disconnects it by session id. Best-effort; any error is ignored.
func killOcservByIP(inboundId int, ip string) {
	sock := fmt.Sprintf("/var/run/ocserv/occtl-%d.sock", inboundId)
	if _, err := os.Stat(sock); err != nil {
		logger.Warning("OpenConnect: cannot evict", ip, "- no occtl socket", sock)
		return
	}
	bin := daemonBin("occtl")
	out, err := probeCmd(bin, "-s", sock, "-j", "show", "users")
	if err != nil {
		logger.Warning("OpenConnect: cannot evict", ip, "- occtl show users failed:", err)
		return
	}
	var users []struct {
		ID   json.Number `json:"ID"`
		IPv4 string      `json:"IPv4"`
	}
	if err := json.Unmarshal(out, &users); err != nil {
		logger.Warning("OpenConnect: cannot evict", ip, "- unreadable occtl output:", err)
		return
	}
	for _, u := range users {
		if u.IPv4 == ip {
			if _, err := probeCmd(bin, "-s", sock, "disconnect", "id", u.ID.String()); err != nil {
				logger.Warning("OpenConnect: occtl disconnect id", u.ID.String(), "failed:", err)
			}
			return
		}
	}
	// Usually benign: the victim's tunnel was already gone, which is why the panel's view
	// of it was stale enough to evict. Logged because the other reading is not benign at
	// all: the caller has already handed this address to the incoming device, and if a
	// victim IS still connected it now shares it. ocserv will not notice (it registers no
	// lease for an explicitly assigned address), and one of the two tunnels then stops
	// receiving while staying connected.
	logger.Infof("OpenConnect: no live ocserv session holds %s, nothing to evict", ip)
}

// KillClient disconnects a user's active session(s) on an inbound's ocserv via
// occtl. Best-effort: a no-op if the socket/daemon isn't up. `disconnect user`
// drops every session for that username (whole-account teardown), which is what
// the disable/expiry callers want. Per-device eviction (User Limit "accept")
// uses `disconnect id` and is layered on in the RADIUS path.
func (s *OcservService) KillClient(inboundId int, username string) {
	if username == "" {
		return
	}
	sock := s.occtlSocket(inboundId)
	if _, err := os.Stat(sock); err != nil {
		return
	}
	// Bounded like every other occtl call on a RADIUS/job path: this runs from the 10s
	// traffic tick, once per disabled client. See vpnProbeTimeout.
	if _, err := probeCmd(s.occtlBinaryPath(), "-s", sock, "disconnect", "user", username); err != nil {
		logger.Debugf("OpenConnect: occtl disconnect user %s failed: %v", username, err)
	}
}

// KillDisabledSessions disconnects active OpenConnect sessions for clients that
// are disabled (in settings or via the client_traffics quota/expiry table).
func (s *OcservService) KillDisabledSessions() {
	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return
	}
	disabledEmails := s.getDisabledEmails()

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if !client.Enable || disabledEmails[client.Email] {
				s.KillClient(inbound.Id, client.ID)
			}
		}
	}
}

// DisableClients disconnects the given client emails' active sessions.
func (s *OcservService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}
	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return
	}
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if emailSet[client.Email] {
				s.KillClient(inbound.Id, client.ID)
			}
		}
	}
}

// getDisabledEmails returns the set of client emails disabled in client_traffics
// (traffic limit or expiry).
func (s *OcservService) getDisabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := database.GetDB()
	var emails []string
	db.Model(&xray.ClientTraffic{}).
		Where("enable = ?", false).
		Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// getServerIP returns the server's primary IP address (default-route source).
func (s *OcservService) getServerIP() string {
	output, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err == nil {
		parts := strings.Fields(string(output))
		for i, p := range parts {
			if p == "src" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (s *OcservService) writeFile(path, content string) error {
	return s.writeFileMode(path, content, 0644)
}

func (s *OcservService) writeFileMode(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func (s *OcservService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("OpenConnect: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
