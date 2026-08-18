package service

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/backend"
	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/json_util"
	"github.com/hasan1808/pro-ui/web/service/rbridge"
	"github.com/hasan1808/pro-ui/xray"
)

// Ikev2Service manages the IKEv2/IPsec protocol via a bundled strongSwan (charon).
//
// Unlike the per-inbound daemons (ocserv, accel-ppp), IKE is fixed to UDP 500/4500,
// so a host can run only ONE IKE daemon. IKEv2 therefore uses a SINGLE shared charon
// process ("ikev2" in the process manager) that serves EVERY ikev2 inbound: each
// inbound becomes a swanctl connection loaded into that one charon via vici. This also
// makes multi-inbound work for free — charon binds 500/4500 once and the panel's
// RADIUS server pins each account to its own inbound's /16 block via Framed-IP-Address,
// so per-inbound source-IP routing through Xray is unchanged from the other protocols.
//
// Auth is server-authoritative like ocserv: strongSwan's eap-radius plugin forwards
// the EAP-MSCHAPv2 conversation to the panel's in-process RADIUS server (127.0.0.1),
// which authenticates the account and returns the Framed-IP-Address charon assigns.
type Ikev2Service struct {
	inboundService InboundService
	nftService     NftService
	radiusService  *RadiusService
	radiusSecret   string
}

// ikev2Settings is the IKEv2-specific slice of an inbound's Settings JSON. It clones
// the ocserv/sstp TLS-cert model and adds an auth-mode selector.
type ikev2Settings struct {
	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`

	// Mtu is the tunnel MTU an IKEv2 client should be held to. 0 means the protocol
	// default (ikev2DefaultMtu).
	//
	// IT IS NOT WRITTEN INTO ANY DAEMON CONFIG, because there is nowhere to write it.
	// IKEv2 has no configuration attribute for an MTU, so a gateway cannot tell a client
	// what to use; and this panel sets `install_routes = no` in strongswan.conf (the
	// routing is ours, via nftables TPROXY), so there is not even a strongSwan-installed
	// route to hang an `mtu`/`advmss` metric on. What the server CAN do is bound the
	// segments each side sends, which is what clampMss is for and what the nftables rules
	// in GenerateVpnRules do with it. See effectiveMtu.
	Mtu int `json:"mtu"`

	// AuthMode selects how clients authenticate:
	//   "eap-mschapv2" (default) — username/password via RADIUS; server presents a cert
	//   "psk"                     — a shared pre-shared key (no per-account RADIUS)
	//   "eap-tls"                 — mutual certificate (client cert); server presents a cert
	AuthMode string `json:"authMode"`
	Psk      string `json:"psk"` // psk mode: the shared secret

	// ServerAddr is the address clients dial (its SAN must match). Defaults to the
	// panel-access host / detected server IP when empty.
	ServerAddr string `json:"serverAddr"`

	// TLS server cert, same model as ocserv/sstp: operator paths (TlsUseFile) or inline
	// PEM. "Generate Self-Signed Cert" fills the content fields (incl. CaCert).
	TlsUseFile      bool   `json:"tlsUseFile"`
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
	Certificate     string `json:"certificate"`
	Key             string `json:"key"`
	CaCert          string `json:"caCert"`

	ClientToClient    bool          `json:"clientToClient"`
	CrossInbound      bool          `json:"crossInbound"`
	UserLimit         *int          `json:"userLimit"`
	UserLimitStrategy string        `json:"userLimitStrategy"`
	IpRanges          []string      `json:"ipRanges"`
	Clients           []ikev2Client `json:"clients"`
}

func (o *ikev2Settings) effectiveRanges() []string { return o.IpRanges }

// ikev2DefaultMtu is what an IKEv2 tunnel gets when the operator names no MTU.
//
// 1400, not the 1420 this used to default to. 1420 is the WireGuard number and it does not
// transfer: WireGuard's overhead is a fixed 60 bytes, while IKEv2 in the field is almost
// always ESP inside UDP because a NAT sits somewhere on the path, and that costs 20 (outer
// IP) + 8 (UDP) + 4 (non-ESP marker/SPI framing) + 8 (sequence) + IV + padding + the
// integrity check value: roughly 73-100 bytes on a 1500 byte path, and more again with
// AES-CBC's block padding. 1420 therefore produces packets the peer has to fragment or
// drop, which is the classic "it connects, small requests work, downloads hang".
//
// The panel's own IKEv2 OUTBOUND driver has always used 1400 for exactly this reason
// (vpnout_ikev2.go, ensureXfrmLink), so the two sides of the same protocol now agree.
const ikev2DefaultMtu = 1400

// effectiveMtu is the inner MTU this inbound's clients are held to: the operator's value,
// else the protocol default.
func (o *ikev2Settings) effectiveMtu() int {
	if o.Mtu > 0 {
		return o.Mtu
	}
	return ikev2DefaultMtu
}

// clampMss is the largest TCP payload that fits the tunnel, i.e. the value to force onto a
// SYN's MSS option. The 40 bytes are the inner IPv4 and TCP headers.
//
// This is the ONLY lever an IKEv2 gateway has over what its clients send (see Mtu), and it
// is the same one the GRE inbound pulls, for the same reason: neither protocol negotiates
// an MTU, and path-MTU discovery through a tunnel is unreliable because the learned value
// lives in a route cache that expires, after which the black hole comes back.
func (o *ikev2Settings) clampMss() int {
	return o.effectiveMtu() - 40
}

// authMode returns the effective auth mode (default eap-mschapv2).
func (o *ikev2Settings) authMode() string {
	m := strings.TrimSpace(o.AuthMode)
	if m == "" {
		return "eap-mschapv2"
	}
	return m
}

// ikev2Client is the minimal client shape parsed from Settings JSON. A dedicated
// struct (like ocservClient) so the UI's extra string fields (tgId, totalGB…) don't
// break json.Unmarshal into typed fields.
type ikev2Client struct {
	ID       string `json:"id"`       // IKEv2 username
	Password string `json:"password"` // IKEv2 password
	Email    string `json:"email"`
	Enable   bool   `json:"enable"`
}

const (
	// ikev2ProcName is the single shared charon process key in the process manager.
	ikev2ProcName = "ikev2"
	// ikev2ConfigRoot holds the generated strongswan.conf.
	ikev2ConfigRoot = "/etc/vpn-ui-ikev2"
	// swanctlDir is charon's compiled-in swanctl config dir (Alpine layout). We write
	// per-inbound connection files under conf.d/ and the certs under the standard subdirs.
	swanctlDir     = "/etc/swanctl"
	swanctlConfDir = swanctlDir + "/conf.d"
	swanctlX509    = swanctlDir + "/x509"
	swanctlX509CA  = swanctlDir + "/x509ca"
	swanctlPrivate = swanctlDir + "/private"
	// viciSocket is charon's control socket swanctl connects to.
	viciSocket = "/var/run/charon.vici"
)

// SetRadius wires the shared RADIUS service + secret for IKEv2 auth/acct.
func (s *Ikev2Service) SetRadius(rs *RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

// getRadiusSecret returns the RADIUS shared secret, falling back to the DB setting
// when the in-memory field is empty (the controller holds a zero-value copy).
func (s *Ikev2Service) getRadiusSecret() string {
	if s.radiusSecret != "" {
		return s.radiusSecret
	}
	var settingService SettingService
	secret, _ := settingService.GetRadiusSecret()
	return secret
}

func (s *Ikev2Service) GetIkev2Inbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "ikev2").Find(&inbounds).Error
	return inbounds, err
}

func (s *Ikev2Service) parseSettings(inbound *model.Inbound) (*ikev2Settings, error) {
	settings := &ikev2Settings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// ikev2BlockFor returns an inbound's client block (10.6.x) network + prefix, mirroring
// ocservBlockFor. The server takes .1; clients start at .2. Defaults to 10.6.{id}.0/24.
func ikev2BlockFor(inbound *model.Inbound, settings *ikev2Settings) (net.IP, int) {
	return vpnBlock(settings.effectiveRanges(), protocolBase("ikev2"), inbound.Id)
}

// GetSubnetForInbound returns the inbound's client block as a CIDR string.
func (s *Ikev2Service) GetSubnetForInbound(inbound *model.Inbound) string {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		settings = &ikev2Settings{}
	}
	netAddr, prefix := ikev2BlockFor(inbound, settings)
	return fmt.Sprintf("%s/%d", netAddr.String(), prefix)
}

// GetSubnetsForInbound returns the inbound's client subnet(s) — one contiguous block,
// like OpenConnect. Used by the nftables TPROXY/accounting path.
func (s *Ikev2Service) GetSubnetsForInbound(inbound *model.Inbound) []string {
	return []string{s.GetSubnetForInbound(inbound)}
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port (shared 12300+id).
func (s *Ikev2Service) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound that captures the
// TPROXY-redirected IKEv2 traffic and feeds it into Xray — identical to the others.
func (s *Ikev2Service) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
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

// charonBin / swanctlBin resolve the bundled launchers (or a host binary from PATH).
func (s *Ikev2Service) charonBin() string {
	if p := backend.StrongswanBinPath("charon"); p != "" {
		return p
	}
	return "charon"
}

func (s *Ikev2Service) swanctlBin() string {
	if p := backend.StrongswanBinPath("swanctl"); p != "" {
		return p
	}
	return "swanctl"
}

// InitIkev2 brings IKEv2 up on panel startup.
func (s *Ikev2Service) InitIkev2() {
	inbounds, err := s.GetIkev2Inbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	logger.Info("IKEv2: initializing services for", len(inbounds), "inbound(s)")
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("IKEv2: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		logger.Warning("IKEv2: failed to setup routing:", err)
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("IKEv2: failed to restart services:", err)
	}
}

// ikev2AdmitSig remembers the admission signature of the swanctl config last written by
// GenerateAllConfigs, so ReconcileDisabled can skip the reload when nothing changed. It
// is package-level because the traffic job drives a zero-value Ikev2Service copy (the
// same reason procMgr and sshMgr are package-level), so per-struct state would be lost.
var (
	ikev2AdmitMu  sync.Mutex
	ikev2AdmitSig string
)

// ikev2Admissible reports whether charon should hold a connection for this inbound at
// all, given the current quota-disabled set.
//
// eap-mschapv2 always keeps its connection: charon forwards every re-auth to the panel's
// in-process RADIUS, which reads client_traffics live and refuses a disabled account.
//
// psk and eap-tls have no such hook. They authenticate locally at charon against
// account-independent criteria (a shared secret, or `eap_id = %any` plus a CA), so a
// disabled account is re-admitted the instant it re-dials. Both are single-account modes
// (Poll asserts this by taking Clients[0]), which makes "this account is disabled"
// equivalent to "this connection must not exist" -- the same contract wg-c gets by
// removing a disabled peer from the device. This is the psk/eap-tls analogue of
// wgc.buildPeers, and it checks both flags for the same reasons: Enable is the operator
// switching the account off, disabled[] is the quota/expiry verdict.
func ikev2Admissible(settings *ikev2Settings, disabled map[string]bool) bool {
	switch settings.authMode() {
	case "psk", "eap-tls":
	default:
		return true
	}
	if len(settings.Clients) == 0 {
		// No account owns the inbound, so there is no account state to enforce.
		// Preserve the pre-existing behavior rather than silently killing the conn.
		return true
	}
	c := settings.Clients[0]
	return c.Enable && !disabled[c.Email]
}

// admissionSig renders the per-inbound admission decisions that GenerateAllConfigs will
// act on. It must walk inbounds exactly as GenerateAllConfigs does, so that an unchanged
// signature provably means an unchanged config.
func (s *Ikev2Service) admissionSig(inbounds []*model.Inbound, disabled map[string]bool) string {
	var b strings.Builder
	for _, inbound := range inbounds {
		b.WriteString(strconv.Itoa(inbound.Id))
		switch {
		case !inbound.Enable:
			b.WriteString(":off;")
		default:
			settings, err := s.parseSettings(inbound)
			switch {
			case err != nil:
				b.WriteString(":err;")
			case ikev2Admissible(settings, disabled):
				b.WriteString(":on;")
			default:
				b.WriteString(":off;")
			}
		}
	}
	return b.String()
}

// ReconcileDisabled re-derives charon's loaded connections from account state, so a
// psk/eap-tls account that just tripped its quota cannot reconnect.
//
// The rbridge sweeper alone is not enough: its Evict only terminates the live IKE SA,
// leaving the connection loaded, so the client re-dials into the next tick's gap and
// keeps browsing. Dropping the connection is what makes the disable stick, and re-adding
// it restores a re-enabled account within one tick.
//
// Reloads only when the admissible set actually changed. Unlike wg-c's netlink diff this
// costs a swanctl --load-all, so a steady state must not pay it: the common tick is one
// small query plus a string compare.
func (s *Ikev2Service) ReconcileDisabled() {
	inbounds, err := s.GetIkev2Inbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}
	sig := s.admissionSig(inbounds, s.getDisabledEmails())
	ikev2AdmitMu.Lock()
	unchanged := sig == ikev2AdmitSig
	ikev2AdmitMu.Unlock()
	if unchanged {
		return
	}
	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("IKEv2: admission reconcile failed:", err)
		return
	}
	// Loads the new config AND unloads any connection no longer in it: swanctl
	// --load-conns removes connections absent from the config files. Live SAs are not
	// torn down by an unload, so the sweeper's Evict stays necessary and complementary:
	// together they give "SA killed AND cannot re-establish".
	if err := s.RestartServices(); err != nil {
		logger.Warning("IKEv2: reload after admission reconcile failed:", err)
	}
}

// GenerateAllConfigs regenerates strongswan.conf + every per-inbound swanctl connection
// + cert files from DB state.
func (s *Ikev2Service) GenerateAllConfigs() error {
	inbounds, err := s.GetIkev2Inbounds()
	if err != nil {
		return err
	}
	if len(inbounds) == 0 {
		return nil
	}

	if err := s.writeStrongswanConf(inbounds); err != nil {
		return err
	}

	// Clean out old per-inbound connection files so a deleted/renamed inbound doesn't
	// linger in swanctl.
	if entries, err := os.ReadDir(swanctlConfDir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "ikev2-") && strings.HasSuffix(e.Name(), ".conf") {
				_ = os.Remove(filepath.Join(swanctlConfDir, e.Name()))
			}
		}
	}

	disabled := s.getDisabledEmails()
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("IKEv2: skipping inbound", inbound.Id, err)
			continue
		}
		// Certs are written either way: they are inert without a connection to use them,
		// and keeping them current means a re-enabled account comes back on the next
		// reload with no cert churn (and no chance of re-minting a cert clients pin).
		if err := s.writeCertFiles(inbound, settings); err != nil {
			logger.Warning("IKEv2: cert write failed for inbound", inbound.Id, err)
		}
		// The connection is the admission decision for psk/eap-tls: omitting it here (so
		// --load-conns unloads it) is what stops a disabled account from reconnecting.
		if !ikev2Admissible(settings, disabled) {
			logger.Debug("IKEv2: inbound", inbound.Id,
				"account disabled or over quota, leaving its connection unloaded")
			continue
		}
		if err := s.writeConnConf(inbound, settings); err != nil {
			logger.Warning("IKEv2: conn config write failed for inbound", inbound.Id, err)
		}
	}
	ikev2AdmitMu.Lock()
	ikev2AdmitSig = s.admissionSig(inbounds, disabled)
	ikev2AdmitMu.Unlock()
	return nil
}

// writeStrongswanConf writes /etc/strongswan.conf: charon plugin config, crucially the
// eap-radius plugin pointed at the panel's in-process RADIUS server on loopback.
func (s *Ikev2Service) writeStrongswanConf(inbounds []*model.Inbound) error {
	dns1, dns2 := "8.8.8.8", "8.8.4.4"
	for _, ib := range inbounds {
		if st, err := s.parseSettings(ib); err == nil {
			if st.Dns1 != "" {
				dns1 = st.Dns1
			}
			if st.Dns2 != "" {
				dns2 = st.Dns2
			}
			break
		}
	}

	_ = os.MkdirAll(ikev2ConfigRoot, 0755)

	var b strings.Builder
	b.WriteString("# Auto-generated by pro-ui IKEv2 service — do not edit\n")
	b.WriteString("charon {\n")
	b.WriteString("    load_modular = yes\n")
	// Allow MULTIPLE concurrent IKE_SAs per account identity. Must be `never`, not `no`:
	// `no` still honors a client's INITIAL_CONTACT notification (which strongSwan clients
	// send on connect), causing the server to delete the account's OTHER SAs — so a 2nd
	// device on one account kills the 1st. `never` disables uniqueness enforcement AND
	// ignores received INITIAL_CONTACT, so multiple devices per account coexist and the
	// panel's RADIUS solely governs the K limit (reject / accept-evict).
	b.WriteString("    uniqueids = never\n")
	// Run as root — do NOT drop privileges. The bundled charon is built on Alpine, whose
	// package creates an `ipsec` user for charon to setuid to after startup; that user
	// does not exist on the target host, so the compiled-in privilege drop aborts charon
	// with "invalid uid/gid - aborting charon". The panel already runs as root and
	// supervises charon (which needs CAP_NET_ADMIN for XFRM anyway), so staying root is
	// correct. (uid 0 exists everywhere.)
	b.WriteString("    user = root\n")
	b.WriteString("    group = root\n")
	// We own routing via nftables TPROXY; charon must NOT install a 0.0.0.0/0 route.
	b.WriteString("    install_routes = no\n")
	b.WriteString("    filelog {\n")
	b.WriteString("        stderr {\n")
	b.WriteString("            default = 1\n")
	b.WriteString("            ike_name = yes\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("    plugins {\n")
	// Pull in the bundled per-plugin defaults (load = yes for the standard plugin set).
	b.WriteString(fmt.Sprintf("        include %s/charon/*.conf\n", backend.StrongswanDefaultConfDir))
	b.WriteString("        eap-radius {\n")
	b.WriteString("            accounting = yes\n")
	b.WriteString("            accounting_interval = 300\n")
	b.WriteString("            servers {\n")
	b.WriteString("                vpnui {\n")
	b.WriteString("                    address = 127.0.0.1\n")
	b.WriteString(fmt.Sprintf("                    secret = %s\n", s.getRadiusSecret()))
	b.WriteString("                    auth_port = 1812\n")
	b.WriteString("                    acct_port = 1813\n")
	b.WriteString("                    nas_identifier = ikev2\n")
	b.WriteString("                }\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("        attr {\n")
	b.WriteString(fmt.Sprintf("            dns = %s, %s\n", dns1, dns2))
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	// Backed up before the first overwrite, exactly as in charon.go's twin of this
	// function: on a host with its own strongSwan these two files are theirs, and
	// swanctl.conf in particular loses every connection they had defined in it.
	ownPrepareHostFile("/etc/strongswan.conf", "ikev2")
	if err := os.WriteFile("/etc/strongswan.conf", []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("write /etc/strongswan.conf: %w", err)
	}

	// swanctl.conf just includes the per-inbound connection files.
	_ = os.MkdirAll(swanctlConfDir, 0755)
	_ = os.MkdirAll(swanctlX509, 0755)
	_ = os.MkdirAll(swanctlX509CA, 0755)
	_ = os.MkdirAll(swanctlPrivate, 0700)
	ownPrepareHostFile(swanctlDir+"/swanctl.conf", "ikev2")
	return os.WriteFile(swanctlDir+"/swanctl.conf", []byte("include conf.d/*.conf\n"), 0600)
}

// certBaseName returns the per-inbound cert/key filename stem.
func (s *Ikev2Service) certBaseName(id int) string { return fmt.Sprintf("ikev2-%d", id) }

// certPaths returns the server cert + key paths charon should load. Path mode uses the
// operator's own files verbatim; content mode uses the swanctl standard dirs.
func (s *Ikev2Service) certPaths(inbound *model.Inbound, settings *ikev2Settings) (certPath, keyPath string) {
	if settings.TlsUseFile && strings.TrimSpace(settings.CertificateFile) != "" && strings.TrimSpace(settings.KeyFile) != "" {
		return strings.TrimSpace(settings.CertificateFile), strings.TrimSpace(settings.KeyFile)
	}
	base := s.certBaseName(inbound.Id)
	return swanctlX509 + "/" + base + "-server.pem", swanctlPrivate + "/" + base + "-server.key"
}

// hasUsableCert reports whether a server cert+key exists (content written, or an
// operator path that exists). charon needs a server cert for EAP/cert modes.
func (s *Ikev2Service) hasUsableCert(inbound *model.Inbound, settings *ikev2Settings) bool {
	certPath, keyPath := s.certPaths(inbound, settings)
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	return true
}

// writeCertFiles publishes the server cert + key into the swanctl credential dirs
// (/etc/swanctl/x509 + /etc/swanctl/private), where writeConnConf's `certs =
// <base>-server.pem` references them and swanctl --load-creds auto-loads the key.
// BOTH modes land here: content mode writes the inline PEM; PATH mode COPIES the
// operator's files (e.g. Let's Encrypt live/…/fullchain.pem + privkey.pem) in — swanctl
// only auto-loads creds from its own dirs, so a bare path reference is never found.
// Copying (re-run on every regenerate) also republishes a renewed cert. Skipping path
// mode (the old behaviour) left the referenced cert absent → the connection failed to
// load → charon had NO config → clients got NO_PROPOSAL_CHOSEN, which the Windows
// built-in IKEv2 client reports as "policy match error".
func (s *Ikev2Service) writeCertFiles(inbound *model.Inbound, settings *ikev2Settings) error {
	_ = os.MkdirAll(swanctlX509, 0755)
	_ = os.MkdirAll(swanctlX509CA, 0755)
	_ = os.MkdirAll(swanctlPrivate, 0700)
	base := s.certBaseName(inbound.Id)

	var certPEM, keyPEM []byte
	if settings.TlsUseFile {
		certPath := strings.TrimSpace(settings.CertificateFile)
		keyPath := strings.TrimSpace(settings.KeyFile)
		if certPath == "" || keyPath == "" {
			return nil
		}
		var err error
		if certPEM, err = os.ReadFile(certPath); err != nil {
			return fmt.Errorf("read ikev2 cert file %q: %w", certPath, err)
		}
		if keyPEM, err = os.ReadFile(keyPath); err != nil {
			return fmt.Errorf("read ikev2 key file %q: %w", keyPath, err)
		}
	} else {
		certPEM = []byte(strings.TrimSpace(settings.Certificate))
		keyPEM = []byte(strings.TrimSpace(settings.Key))
		// A separately-pasted CA chain (content mode) is appended so its intermediates
		// are split out and sent alongside the leaf, just like a bundled fullchain.
		if ca := strings.TrimSpace(settings.CaCert); ca != "" {
			certPEM = append(append(certPEM, '\n'), ca...)
		}
	}
	if len(certPEM) == 0 {
		return nil
	}
	if err := s.publishServerCert(base, certPEM, keyPEM); err != nil {
		return err
	}
	// eap-tls: charon validates CLIENT certs against the CAs loaded in x509ca. Publish
	// the inbound's CA there as an explicit trust anchor. publishServerCert deliberately
	// skips self-signed roots (correct for the server's own chain), which would drop a
	// self-signed client-signing CA, so write it under its own name here. Removed when
	// the inbound is not eap-tls so a stale anchor never lingers.
	clientCAPath := swanctlX509CA + "/" + base + "-clientca.pem"
	if settings.authMode() == "eap-tls" && strings.TrimSpace(settings.CaCert) != "" {
		if err := os.WriteFile(clientCAPath, []byte(strings.TrimSpace(settings.CaCert)), 0644); err != nil {
			return err
		}
	} else {
		_ = os.Remove(clientCAPath)
	}
	return nil
}

// publishServerCert writes the leaf to x509/<base>-server.pem and EACH intermediate CA
// cert (every non-leaf, non-self-signed cert in the bundle) to its OWN
// x509ca/<base>-chainN.pem file. Two subtleties, both learned the hard way against the
// Windows client:
//   - swanctl --load-creds loads only the FIRST certificate from a file, so a combined
//     chain file loads only one intermediate; charon then sends an incomplete chain and
//     Windows fails with "IKE authentication credentials are unacceptable". One file per
//     intermediate fixes it (Let's Encrypt's deep chain needs 2+ intermediates sent).
//   - self-signed roots are skipped — the client already trusts those; sending them is
//     pointless and charon won't relay a trust anchor anyway.
func (s *Ikev2Service) publishServerCert(base string, certPEM, keyPEM []byte) error {
	if err := os.WriteFile(swanctlX509+"/"+base+"-server.pem", certPEM, 0644); err != nil {
		return err
	}
	// Clear this inbound's stale intermediate files so a shortened chain doesn't linger.
	if entries, err := os.ReadDir(swanctlX509CA); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), base+"-chain") {
				_ = os.Remove(filepath.Join(swanctlX509CA, e.Name()))
			}
		}
	}
	rest := certPEM
	idx, n := 0, 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		idx++
		if idx == 1 {
			continue // the leaf; it goes in x509/ as the identity cert
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil || bytes.Equal(crt.RawSubject, crt.RawIssuer) {
			continue // unparseable, or a self-signed root the client already has
		}
		n++
		if err := os.WriteFile(fmt.Sprintf("%s/%s-chain%d.pem", swanctlX509CA, base, n), pem.EncodeToMemory(block), 0644); err != nil {
			return err
		}
	}
	if len(keyPEM) > 0 {
		return os.WriteFile(swanctlPrivate+"/"+base+"-server.key", keyPEM, 0600)
	}
	return nil
}

// serverID returns the IKE identity the server presents — the dialed address, which
// must match a SAN in the server cert. Falls back to the detected server IP.
func (s *Ikev2Service) serverID(settings *ikev2Settings) string {
	if a := strings.TrimSpace(settings.ServerAddr); a != "" {
		return a
	}
	if ip := s.getServerIP(); ip != "" {
		return ip
	}
	return "vpn-ui"
}

// ResolveServerID is serverID for callers outside this file (the account-export "Remote
// ID" endpoint) that only have the inbound, not an already-parsed settings struct. Kept
// as a thin wrapper rather than exporting serverID/ikev2Settings themselves, since those
// stay package-private like every other protocol's settings shape.
func (s *Ikev2Service) ResolveServerID(inbound *model.Inbound) (string, error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return "", err
	}
	return s.serverID(settings), nil
}

// ikev2PoolName is the swanctl pool name for an eap-tls inbound's local address pool.
func ikev2PoolName(base string) string { return base + "-pool" }

// ikev2PoolDNS renders the inbound's DNS servers as a swanctl pool `dns =` value.
func ikev2PoolDNS(settings *ikev2Settings) string {
	var parts []string
	if d := strings.TrimSpace(settings.Dns1); d != "" {
		parts = append(parts, d)
	}
	if d := strings.TrimSpace(settings.Dns2); d != "" {
		parts = append(parts, d)
	}
	return strings.Join(parts, ", ")
}

// serverCertKeyType returns the leaf server cert's public-key algorithm
// ("RSA", "ECDSA", "Ed25519", …) from the first CERTIFICATE block of certPEM.
func serverCertKeyType(certPEM []byte) (string, error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return "", fmt.Errorf("no certificate found in PEM")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		return crt.PublicKeyAlgorithm.String(), nil
	}
}

// ikev2CertWarning returns a device-compatibility warning for a non-RSA IKEv2
// server cert (empty string for RSA). Live-verified: iOS silently rejects ECDSA
// server certs (connects then drops with no error); Windows and Android accept them.
func ikev2CertWarning(keyType string) string {
	if keyType == "" || strings.EqualFold(keyType, "RSA") {
		return ""
	}
	return fmt.Sprintf("This server certificate uses a %s key. Apple and iOS devices "+
		"silently reject non-RSA (such as ECDSA) IKEv2 server certificates and fail "+
		"to connect with no error message. Windows and Android accept them. Use an "+
		"RSA certificate for broad device compatibility.", keyType)
}

// InspectServerCert reads an ikev2 inbound's configured server cert (path or inline
// PEM) and returns its public-key type plus a device-compatibility warning. An empty
// keyType with a nil error means no cert is configured yet (nothing to check) — e.g.
// PSK mode, or an as-yet-unfilled cert.
func (s *Ikev2Service) InspectServerCert(inbound *model.Inbound) (keyType, warning string, err error) {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return "", "", err
	}
	if settings.authMode() == "psk" {
		return "", "", nil
	}
	var certPEM []byte
	if settings.TlsUseFile {
		p := strings.TrimSpace(settings.CertificateFile)
		if p == "" {
			return "", "", nil
		}
		if certPEM, err = os.ReadFile(p); err != nil {
			return "", "", fmt.Errorf("read cert file %q: %w", p, err)
		}
	} else {
		certPEM = []byte(strings.TrimSpace(settings.Certificate))
	}
	if len(certPEM) == 0 {
		return "", "", nil
	}
	kt, err := serverCertKeyType(certPEM)
	if err != nil {
		return "", "", err
	}
	return kt, ikev2CertWarning(kt), nil
}

// writeConnConf writes /etc/swanctl/conf.d/ikev2-<id>.conf: one connection definition
// for the inbound, keyed by its auth mode.
func (s *Ikev2Service) writeConnConf(inbound *model.Inbound, settings *ikev2Settings) error {
	base := s.certBaseName(inbound.Id)
	_ = os.MkdirAll(swanctlConfDir, 0755)
	return os.WriteFile(swanctlConfDir+"/"+base+".conf",
		[]byte(applyCoreConfigOverride("ikev2", inbound.Id, base+".conf",
			s.buildConnConf(inbound, settings))), 0600)
}

// buildConnConf renders the body. Split from the write so the config editor can show the
// operator the GENERATED text they are diverging from; the file on disk already has
// their override merged in.
func (s *Ikev2Service) buildConnConf(inbound *model.Inbound, settings *ikev2Settings) string {
	base := s.certBaseName(inbound.Id)
	id := s.serverID(settings)

	var b strings.Builder
	b.WriteString("# Auto-generated by pro-ui IKEv2 service — do not edit\n")
	b.WriteString("connections {\n")
	b.WriteString(fmt.Sprintf("    %s {\n", base))
	b.WriteString("        version = 2\n")
	// Connection-level uniqueness policy — the per-connection twin of charon.uniqueids.
	// Must be `never` (not `no`): `no` still honors a client's INITIAL_CONTACT and deletes
	// the account's other SAs; `never` ignores INITIAL_CONTACT so multiple devices on one
	// account (same EAP identity) hold concurrent IKE_SAs. The panel RADIUS governs the K
	// limit. Without `never` two devices on one account flap (kick each other).
	b.WriteString("        unique = never\n")
	// Tunnel-IP source per auth mode. eap-mschapv2 gets a per-account
	// Framed-IP-Address from the panel RADIUS (pools = radius). psk and eap-tls
	// authenticate locally at charon (no RADIUS round-trip), so they draw from a
	// local pool spanning the inbound's whole client block; the account is mapped to
	// that block for routing and the reconcile sweep enforces the User Limit.
	switch settings.authMode() {
	case "eap-tls", "psk":
		b.WriteString(fmt.Sprintf("        pools = %s\n", ikev2PoolName(base)))
	default:
		b.WriteString("        pools = radius\n")
	}
	b.WriteString("        rekey_time = 4h\n")
	// IKE proposals. Strong groups (MODP2048/ECP256 + `default`) come first so capable
	// clients negotiate them, but the tail explicitly includes MODP_1024 (DH group 2):
	// the WINDOWS built-in IKEv2 client offers ONLY group 2 by default, and strongSwan
	// drops MODP1024 from `default` as weak — so without these a stock Windows client
	// gets "received proposals unacceptable" → NO_PROPOSAL_CHOSEN → "policy match error".
	b.WriteString("        proposals = aes256-sha256-modp2048,aes256gcm16-prfsha256-ecp256,aes256gcm16-prfsha256-modp1024,aes256-sha256-modp1024,aes128-sha256-modp1024,aes256-sha1-modp1024,default\n")
	b.WriteString("        send_cert = always\n")
	b.WriteString("        fragmentation = yes\n")
	b.WriteString("        dpd_delay = 300s\n")

	switch settings.authMode() {
	case "psk":
		// Shared pre-shared key. No per-account RADIUS identity — a single secret.
		b.WriteString("        local {\n            auth = psk\n        }\n")
		b.WriteString("        remote {\n            auth = psk\n        }\n")
	case "eap-tls":
		// Mutual certificate: server cert + client certs (validated against the CA).
		b.WriteString("        local {\n")
		b.WriteString("            auth = pubkey\n")
		b.WriteString(fmt.Sprintf("            certs = %s-server.pem\n", base))
		b.WriteString(fmt.Sprintf("            id = %s\n", id))
		b.WriteString("        }\n")
		b.WriteString("        remote {\n            auth = eap-tls\n            eap_id = %any\n        }\n")
	default: // eap-mschapv2
		b.WriteString("        local {\n")
		b.WriteString("            auth = pubkey\n")
		b.WriteString(fmt.Sprintf("            certs = %s-server.pem\n", base))
		b.WriteString(fmt.Sprintf("            id = %s\n", id))
		b.WriteString("        }\n")
		b.WriteString("        remote {\n            auth = eap-radius\n            eap_id = %any\n        }\n")
	}

	b.WriteString("        children {\n")
	b.WriteString("            net {\n")
	b.WriteString("                local_ts = 0.0.0.0/0\n")
	// ESP proposals — include the AES-CBC + SHA1/SHA256 (no-PFS) suites the Windows
	// client offers for the CHILD_SA, alongside AES-GCM for modern clients.
	b.WriteString("                esp_proposals = aes256gcm16,aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,default\n")
	b.WriteString("                rekey_time = 1h\n")
	b.WriteString("            }\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")

	// psk / eap-tls local address pool: charon leases each device a tunnel IP from
	// the inbound's whole client block. The account is mapped to that block CIDR for
	// routing (BuildVpnEmailToIPMap), so every pool address flows through Xray, and
	// the reconcile sweep enforces the User Limit K + strategy on top (charon has no
	// connect-time hook for locally-authenticated modes).
	if m := settings.authMode(); m == "eap-tls" || m == "psk" {
		if blockNet, prefix := ikev2BlockFor(inbound, settings); blockNet != nil {
			b.WriteString("pools {\n")
			b.WriteString(fmt.Sprintf("    %s {\n", ikev2PoolName(base)))
			b.WriteString(fmt.Sprintf("        addrs = %s/%d\n", blockNet.String(), prefix))
			if dns := ikev2PoolDNS(settings); dns != "" {
				b.WriteString(fmt.Sprintf("        dns = %s\n", dns))
			}
			b.WriteString("    }\n")
			b.WriteString("}\n")
		}
	}

	// PSK mode needs the secret in a secrets{} block.
	if settings.authMode() == "psk" && strings.TrimSpace(settings.Psk) != "" {
		b.WriteString("secrets {\n")
		b.WriteString(fmt.Sprintf("    ike-%s {\n        secret = %s\n    }\n", base, settings.Psk))
		b.WriteString("}\n")
	}

	return b.String()
}

// SetupRouting prepares the host so IKEv2 client traffic is TPROXY-redirected into
// Xray. Shares the fwmark policy route + nftables regeneration with the other VPN
// protocols. The IPsec ESP data plane needs the XFRM kernel stack (built-in on target
// kernels, same as the L2TP/IPsec path).
func (s *Ikev2Service) SetupRouting() error {
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
	// Best-effort XFRM/ESP module preload (built-in on most kernels).
	s.runCmd("modprobe", "esp4")
	s.runCmd("modprobe", "xfrm_user")

	ensureVpnPolicyRoute(s.runCmd)
	return s.nftService.ApplyNftRules()
}

// RestartServices ensures the single shared charon is running and (re)loads every
// swanctl connection. charon is only (re)started when it isn't already up, so a client
// add/remove reloads via vici without dropping live tunnels. When no ikev2 inbound has
// a usable cert, charon is stopped.
func (s *Ikev2Service) RestartServices() error {
	migrateFromSystemd()
	// The one bundled charon serves BOTH IKEv2 and L2TP/IPsec now, so the start/stop
	// decision must consider both protocols: syncCharon starts, reloads, or stops charon
	// based on whether EITHER an IKEv2 inbound or an L2TP+IPsec inbound still needs it.
	// This prevents removing the last IKEv2 inbound from killing a live L2TP/IPsec (and
	// vice versa). Per-inbound ikev2 conns/certs were already written by GenerateAllConfigs.
	return syncCharon()
}

// StopServices stops the shared charon process.
func (s *Ikev2Service) StopServices() error {
	return procMgr.Stop(ikev2ProcName)
}

// GenerateSelfSignedCert generates an RSA CA + server leaf for IKEv2. IKEv2 needs a
// CA→leaf chain (the client trusts the CA) with a SAN matching the dialed address, a
// serverAuth EKU, and RSA keys (native iOS/Windows clients reject ECDSA server certs
// and require the SAN). Returns PEM strings: serverCert, serverKey, caCert.
func (s *Ikev2Service) GenerateSelfSignedCert(serverAddr string) (string, string, string, error) {
	host := strings.TrimSpace(serverAddr)
	if host == "" {
		host = s.getServerIP()
	}
	cn := host
	if cn == "" {
		cn = "pro-ui IKEv2 Server"
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", fmt.Errorf("generate CA key: %w", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{Organization: []string{"pro-ui"}, CommonName: "vpn-ui IKEv2 CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return "", "", "", err
	}

	srvKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", fmt.Errorf("generate server key: %w", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{Organization: []string{"pro-ui"}, CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if host != "" {
		// Add both a dNSName and (when it parses) an iPAddress SAN. Windows connect-by-IP
		// requires the IP to appear as a dNSName, so include it in DNSNames too.
		leafTmpl.DNSNames = []string{host}
		if ip := net.ParseIP(host); ip != nil {
			leafTmpl.IPAddresses = []net.IP{ip}
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return string(certPEM), string(keyPEM), string(caPEM), nil
}

// killIkev2ByIP terminates the IKE SA whose client virtual IP matches, via swanctl.
// The panel's User-Limit "accept" eviction calls this (radius.go). swanctl has no
// disconnect-by-IP, so list the SAs, find the one whose remote traffic selector /
// virtual IP is `ip`, and terminate it by IKE-SA unique id. Best-effort.
func (s *Ikev2Service) KillClientIP(inbound *model.Inbound, ip string) error {
	killIkev2ByIP(s.swanctlBin(), ip)
	return nil
}

// ikev2IPActive reports whether any live IKE SA still holds the virtual IP `ip`, via
// swanctl. Used by the RADIUS liveness probe (isIPActive) for stale-session reconcile.
func ikev2IPActive(ip string) bool {
	return ikev2SAIDForIP((&Ikev2Service{}).swanctlBin(), ip) != ""
}

// ikeSAHeaderRe matches an IKE-SA header line ("ikev2-6: #7, ESTABLISHED, ..."),
// which swanctl prints flush-left at column 0. It MUST be applied to the raw,
// UN-trimmed line: every sub-line of an SA is indented, and the child SA line is
// literally "  net: #12, reqid 1, INSTALLED, ..." — after TrimSpace it also matches
// this pattern and would clobber the IKE-SA id with the (unrelated) child-SA id, so
// a later `--terminate --ike-id <child-id>` targets nothing and the SA survives.
// That was the strategy-accept eviction bug: the evicted device never actually died.
var ikeSAHeaderRe = regexp.MustCompile(`^[^\s:]+:\s+#(\d+),`)

// ikev2SAIDForIP returns the unique id of the OLDEST (lowest unique-id) IKE SA whose
// client virtual IP is `ip`, or "" if no live SA holds it. Parses `swanctl --list-sas`;
// matches the header on the raw line so indented child/vip sub-lines can't overwrite the
// id (see ikeSAHeaderRe). "Oldest" matters for User-Limit accept-eviction: charon's
// unique-ids increase monotonically, so when the freed IP is briefly held by BOTH the
// evicted device and its just-admitted replacement (which reuses the same vip), the
// lowest id is always the device to evict — never the newcomer.
func ikev2SAIDForIP(swanctl, ip string) string {
	if ip == "" {
		return ""
	}
	out, err := exec.Command(swanctl, "--list-sas").CombinedOutput()
	if err != nil {
		return ""
	}
	curID := ""
	best := -1
	target32 := ip + "/32"
	for _, ln := range strings.Split(string(out), "\n") {
		if m := ikeSAHeaderRe.FindStringSubmatch(ln); m != nil {
			curID = m[1]
			continue
		}
		if curID == "" {
			continue
		}
		// The client's assigned IP appears as the child SA remote TS (10.6.x.y/32) or
		// as a remote virtual IP entry ("remote-vips: [10.6.x.y]" / "[10.6.x.y]").
		if strings.Contains(ln, target32) || strings.Contains(ln, "remote-vips: ["+ip) || strings.Contains(ln, "["+ip+"]") {
			if n, e := strconv.Atoi(curID); e == nil && (best < 0 || n < best) {
				best = n
			}
			curID = "" // one match per SA block; keep scanning for an older SA
		}
	}
	if best < 0 {
		return ""
	}
	return strconv.Itoa(best)
}

// killIkev2ByIP terminates the oldest IKE SA holding virtual IP `ip`. Best-effort,
// idempotent. It MUST always run OFF the RADIUS auth path (a goroutine for accept-
// eviction, the disable/expiry sweep otherwise): killIkev2ByIP calls `swanctl
// --list-sas`, which BLOCKS on any IKE_SA that is mid-authentication (charon holds that
// SA's manager lock while its worker thread waits on the RADIUS server) — so calling it
// synchronously inside the auth handler that the mid-auth SA is waiting on deadlocks
// until charon's ~14s RADIUS timeout, failing the new device. Async, list-sas is instant.
func killIkev2ByIP(swanctl, ip string) {
	id := ikev2SAIDForIP(swanctl, ip)
	if id == "" {
		return
	}
	_ = exec.Command(swanctl, "--terminate", "--ike-id", id).Run()
}

// ikev2SA is one IKE_SA parsed from `swanctl --list-sas`: its charon unique-id
// (monotonic, lower = older), its connection name (== certBaseName, "ikev2-<id>"),
// and the virtual IP charon assigned the peer.
type ikev2SA struct {
	id   int
	conn string
	vip  string
}

var (
	// Matched on the RAW line: an IKE_SA header ("ikev2-6: #7, ...") starts at column
	// 0, while indented child-SA lines never match `^\S+`, so they cannot be mistaken
	// for a new SA.
	ikeSAConnHeaderRe = regexp.MustCompile(`^(\S+):\s+#(\d+),`)
	// The assigned virtual IP appears either as "remote-vips: [10.6.x.y]" on the
	// IKE_SA or as "remote 10.6.x.y/32" on the child traffic selector.
	ikev2VipRe = regexp.MustCompile(`(?:remote-vips:\s*\[|remote\s+)(10\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
)

// ikev2ListSAs parses every IKE_SA once. Each header line opens a new SA; the first
// vip-bearing line beneath it fills the vip.
func ikev2ListSAs(swanctl string) []ikev2SA {
	out, err := exec.Command(swanctl, "--list-sas").CombinedOutput()
	if err != nil {
		return nil
	}
	var sas []ikev2SA
	cur := -1
	for _, ln := range strings.Split(string(out), "\n") {
		if m := ikeSAConnHeaderRe.FindStringSubmatch(ln); m != nil {
			id, _ := strconv.Atoi(m[2])
			sas = append(sas, ikev2SA{id: id, conn: m[1]})
			cur = len(sas) - 1
			continue
		}
		if cur >= 0 && sas[cur].vip == "" {
			if m := ikev2VipRe.FindStringSubmatch(ln); m != nil {
				sas[cur].vip = m[1]
			}
		}
	}
	return sas
}

// killIkev2ByID terminates the IKE_SA with the given charon unique-id.
func killIkev2ByID(swanctl string, id int) {
	_ = exec.Command(swanctl, "--terminate", "--ike-id", strconv.Itoa(id)).Run()
}

// Ikev2Service is a rbridge.Adapter for the LOCAL-auth ikev2 modes (psk, eap-tls). Those
// authenticate at charon without a RADIUS round-trip, so the rbridge Sweeper (not RADIUS) tracks
// their sessions, bills their traffic, and enforces quota + User Limit K + strategy each tick.
// eap-mschapv2 inbounds are owned by RADIUS and are skipped by Poll. The Sweeper runs in the
// traffic-job goroutine (never an auth handler), so these methods may call swanctl synchronously.
var _ rbridge.Adapter = (*Ikev2Service)(nil)

// Protocol identifies the sessions this adapter reconciles.
func (s *Ikev2Service) Protocol() string { return "ikev2" }

// Poll lists the live psk/eap-tls tunnels, each attributed to its inbound's single account. The
// charon SA unique-id (monotonic, lower = older) is carried as both the eviction handle
// (DeviceKey) and, via Since, the age used for oldest-first User-Limit eviction.
func (s *Ikev2Service) Poll() ([]rbridge.Live, error) {
	inbounds, err := s.GetIkev2Inbounds()
	if err != nil {
		return nil, err
	}
	swanctl := s.swanctlBin()
	sas := ikev2ListSAs(swanctl)
	var live []rbridge.Live
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		if m := settings.authMode(); m != "psk" && m != "eap-tls" {
			continue // eap-mschapv2 is tracked by the RADIUS accounting path
		}
		if len(settings.Clients) == 0 {
			continue
		}
		account := settings.Clients[0] // psk/eap-tls = exactly one account per inbound
		conn := s.certBaseName(inbound.Id)
		for _, sa := range sas {
			if sa.conn == conn && sa.vip != "" {
				live = append(live, rbridge.Live{
					Protocol:  "ikev2",
					InboundID: inbound.Id,
					Email:     account.Email,
					IP:        sa.vip,
					DeviceKey: strconv.Itoa(sa.id),
					Disabled:  !account.Enable,
					Since:     time.Unix(0, int64(sa.id)),
				})
			}
		}
	}
	return live, nil
}

// Limit returns the inbound's User Limit K and normalized strategy. Unknown inbound -> no limit.
func (s *Ikev2Service) Limit(inboundID int) (int, string) {
	inbounds, err := s.GetIkev2Inbounds()
	if err != nil {
		return 0, ""
	}
	for _, inbound := range inbounds {
		if inbound.Id != inboundID {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			return 0, ""
		}
		return effectiveUserLimit(settings.UserLimit), normUserLimitStrategy(settings.UserLimitStrategy)
	}
	return 0, ""
}

// Evict terminates one live tunnel by its charon SA unique-id (best-effort). killIkev2ByID lists
// SAs, so it must run off the auth path; the Sweeper calls it from the traffic-job goroutine.
func (s *Ikev2Service) Evict(l rbridge.Live) error {
	id, err := strconv.Atoi(l.DeviceKey)
	if err != nil {
		return err
	}
	killIkev2ByID(s.swanctlBin(), id)
	return nil
}

// KillDisabledSessions terminates active IKEv2 sessions for disabled/expired clients.
func (s *Ikev2Service) KillDisabledSessions() {
	inbounds, err := s.GetIkev2Inbounds()
	if err != nil {
		return
	}
	disabled := s.getDisabledEmails()
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, c := range settings.Clients {
			if !c.Enable || disabled[c.Email] {
				s.killByUser(c.ID)
			}
		}
	}
}

// DisableClients terminates the given client emails' active sessions.
func (s *Ikev2Service) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}
	set := make(map[string]bool, len(emails))
	for _, e := range emails {
		set[e] = true
	}
	inbounds, err := s.GetIkev2Inbounds()
	if err != nil {
		return
	}
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, c := range settings.Clients {
			if set[c.Email] {
				s.killByUser(c.ID)
			}
		}
	}
}

// killByUser terminates every IKE SA whose remote EAP identity is `user`.
func (s *Ikev2Service) killByUser(user string) {
	if user == "" {
		return
	}
	swanctl := s.swanctlBin()
	out, err := exec.Command(swanctl, "--list-sas").CombinedOutput()
	if err != nil {
		return
	}
	curID := ""
	needle := "'" + user + "'"
	for _, ln := range strings.Split(string(out), "\n") {
		if m := ikeSAHeaderRe.FindStringSubmatch(ln); m != nil {
			curID = m[1]
			continue
		}
		if curID != "" && strings.Contains(ln, "remote") && strings.Contains(ln, needle) {
			_ = exec.Command(swanctl, "--terminate", "--ike-id", curID).Run()
			curID = ""
		}
	}
}

func (s *Ikev2Service) getDisabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := database.GetDB()
	var emails []string
	db.Model(&xray.ClientTraffic{}).Where("enable = ?", false).Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// getServerIP returns the server's primary (default-route source) IP.
func (s *Ikev2Service) getServerIP() string {
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

func (s *Ikev2Service) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("IKEv2: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
