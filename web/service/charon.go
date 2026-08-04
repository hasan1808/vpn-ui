package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// The bundled strongSwan charon is a SINGLE shared daemon (procMgr key ikev2ProcName)
// that serves BOTH IKEv2 (per-inbound conf.d/ikev2-<id>.conf) and, since we unified the
// IPsec layer, L2TP/IPsec IKEv1 transport (conf.d/l2tp.conf). It owns UDP 500/4500 for
// both, which removes the old charon-vs-pluto (libreswan) port collision. This file holds
// the charon lifecycle both the ikev2 and l2tp services drive; swanctl.conf's
// `include conf.d/*.conf` loads every connection with one `swanctl --load-all`.

// charonBin / swanctlBin resolve the bundled launchers (or a host binary from PATH).
func charonBin() string {
	if p := backend.StrongswanBinPath("charon"); p != "" {
		return p
	}
	return "charon"
}

func swanctlBin() string {
	if p := backend.StrongswanBinPath("swanctl"); p != "" {
		return p
	}
	return "swanctl"
}

// charonNeeded reports whether the shared charon should be running: true when any
// enabled IKEv2 inbound exists, or any enabled L2TP inbound has IPsec enabled, or any
// enabled GRE inbound has IPsec enabled (GRE-over-IPsec is ESP transport on this same
// daemon), or any enabled client-side OUTBOUND needs it.
//
// The outbound clause is not symmetry for its own sake. syncCharon runs from every
// inbound save, and this daemon is shared: on a box that dials out over IKEv2 but
// serves no IPsec inbound of its own, counting inbounds alone answers "not needed"
// and stops charon out from under a live outbound. The tunnel then drops on an
// unrelated edit to some other protocol's inbound, which is about as far from the
// apparent cause as a failure gets.
func charonNeeded() bool {
	db := database.GetDB()
	if db == nil {
		return false
	}
	if vpnOutboundNeedsCharon() {
		return true
	}
	var ikev2Count int64
	db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", "ikev2", true).Count(&ikev2Count)
	if ikev2Count > 0 {
		return true
	}
	var l2tps []*model.Inbound
	db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", "l2tp", true).Find(&l2tps)
	for _, ib := range l2tps {
		if l2tpInboundHasIpsec(ib) {
			return true
		}
	}
	var gres []*model.Inbound
	db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", "gre", true).Find(&gres)
	for _, ib := range gres {
		if greInboundHasIpsec(ib) {
			return true
		}
	}
	return false
}

// vpnOutboundNeedsCharon reports whether any enabled client tunnel rides this daemon:
// an IKEv2 outbound always does, an L2TP one does when it carries a PSK (which is how
// the L2TP/IPsec transport leg is configured on both sides), and a GRE one does when
// it is wrapped in IPsec.
//
// Every kind whose settings decide it reads ONE field, matched against the driver's
// own json tag. Keep this switch in step with the drivers: a kind that rides charon
// and is missing here fails silently, as a tunnel that dies on an unrelated inbound
// save rather than as anything pointing at this function.
//
// Read off the stored tunnel list rather than asked of the drivers, because the answer
// is needed while deciding whether to STOP charon, which is exactly when a driver may
// already have been torn down and would report nothing.
func vpnOutboundNeedsCharon() bool {
	var svc VpnOutboundService
	// listRaw, not List: List masks driver-declared secrets for the panel, and the psk
	// below is exactly such a secret. Reading it through the masked view would find
	// nothing, answer "no IPsec outbound", and stop charon under a live tunnel.
	for _, c := range svc.listRaw() {
		if !c.Enable {
			continue
		}
		switch c.Kind {
		case VpnOutIKEv2:
			return true
		case VpnOutL2TP:
			// The settings blob is the driver's shape, so this looks only for the one
			// field that decides it rather than unmarshalling something this file
			// would then have to keep in step.
			//
			// The tag has to match l2tpOutSettings.IpsecPsk exactly. A near miss here
			// does not fail loudly: the branch simply never fires, and the symptom is
			// a live L2TP/IPsec tunnel dropping when somebody saves an unrelated
			// inbound, which points nowhere near this line.
			var s struct {
				IpsecPsk string `json:"ipsecPsk"`
			}
			if len(c.Settings) > 0 && json.Unmarshal(c.Settings, &s) == nil && s.IpsecPsk != "" {
				return true
			}
		case VpnOutGre:
			// GRE-over-IPsec is ESP transport on this same daemon, exactly as the GRE
			// INBOUND clause above already accounts for.
			var s struct {
				IpsecEnable bool `json:"ipsecEnable"`
			}
			if len(c.Settings) > 0 && json.Unmarshal(c.Settings, &s) == nil && s.IpsecEnable {
				return true
			}
		}
	}
	return false
}

// l2tpInboundHasIpsec reports whether an l2tp inbound has IPsec enabled (ipsecEnable
// defaults to true when the key is absent, matching the l2tp settings model).
func l2tpInboundHasIpsec(inbound *model.Inbound) bool {
	if inbound == nil {
		return false
	}
	var st struct {
		IpsecEnable *bool `json:"ipsecEnable"`
	}
	_ = json.Unmarshal([]byte(inbound.Settings), &st)
	return st.IpsecEnable == nil || *st.IpsecEnable
}

// charonDNS returns the DNS servers to advertise (IKEv2 pools use them; L2TP gets DNS
// from PPP, so this only matters for ikev2). Falls back to public resolvers.
func charonDNS() (string, string) {
	dns1, dns2 := "8.8.8.8", "8.8.4.4"
	db := database.GetDB()
	if db == nil {
		return dns1, dns2
	}
	var ikev2s []*model.Inbound
	db.Model(&model.Inbound{}).Where("protocol = ? AND enable = ?", "ikev2", true).Find(&ikev2s)
	for _, ib := range ikev2s {
		var st struct {
			Dns1 string `json:"dns1"`
			Dns2 string `json:"dns2"`
		}
		if json.Unmarshal([]byte(ib.Settings), &st) == nil {
			if st.Dns1 != "" {
				dns1 = st.Dns1
			}
			if st.Dns2 != "" {
				dns2 = st.Dns2
			}
			break
		}
	}
	return dns1, dns2
}

// writeCharonConf writes /etc/strongswan.conf (shared charon config incl. the eap-radius
// plugin for IKEv2 EAP-MSCHAPv2, harmless to L2TP) + /etc/swanctl/swanctl.conf (which
// includes every conf.d/*.conf: ikev2-<id>.conf and l2tp.conf). Written whenever charon
// is needed by either protocol, so an L2TP-only box also gets a valid config to boot on.
func writeCharonConf() error {
	dns1, dns2 := charonDNS()
	var settingService SettingService
	radiusSecret, _ := settingService.GetRadiusSecret()

	_ = os.MkdirAll(ikev2ConfigRoot, 0755)

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui (shared charon) - do not edit\n")
	b.WriteString("charon {\n")
	b.WriteString("    load_modular = yes\n")
	// `never` (not `no`): ignore INITIAL_CONTACT so multiple devices per account coexist;
	// the panel RADIUS governs the K limit for IKEv2.
	b.WriteString("    uniqueids = never\n")
	// Stay root: the bundled charon (Alpine build) would setuid to a nonexistent `ipsec`
	// user and abort. The panel runs as root and needs CAP_NET_ADMIN for XFRM anyway.
	b.WriteString("    user = root\n")
	b.WriteString("    group = root\n")
	// We own routing via nftables TPROXY; charon must NOT install a 0.0.0.0/0 route. This
	// only suppresses route installation, not the transport/tunnel XFRM policies.
	b.WriteString("    install_routes = no\n")
	b.WriteString("    filelog {\n")
	b.WriteString("        stderr {\n")
	b.WriteString("            default = 1\n")
	b.WriteString("            ike_name = yes\n")
	b.WriteString("        }\n")
	b.WriteString("    }\n")
	b.WriteString("    plugins {\n")
	b.WriteString(fmt.Sprintf("        include %s/charon/*.conf\n", backend.StrongswanDefaultConfDir))
	b.WriteString("        eap-radius {\n")
	b.WriteString("            accounting = yes\n")
	b.WriteString("            accounting_interval = 300\n")
	b.WriteString("            servers {\n")
	b.WriteString("                vpnui {\n")
	b.WriteString("                    address = 127.0.0.1\n")
	b.WriteString(fmt.Sprintf("                    secret = %s\n", radiusSecret))
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

	if err := os.WriteFile("/etc/strongswan.conf", []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("write /etc/strongswan.conf: %w", err)
	}

	_ = os.MkdirAll(swanctlConfDir, 0755)
	_ = os.MkdirAll(swanctlX509, 0755)
	_ = os.MkdirAll(swanctlX509CA, 0755)
	_ = os.MkdirAll(swanctlPrivate, 0700)
	return os.WriteFile(swanctlDir+"/swanctl.conf", []byte("include conf.d/*.conf\n"), 0600)
}

// ensureCharonRunning extracts/links the strongswan bundle and starts the shared charon
// (procMgr key ikev2ProcName) if it isn't already up, waiting for its vici socket.
// Idempotent; never drops live SAs when charon is already running.
func ensureCharonRunning() error {
	// Extract the bundle only if absent: re-extracting under a running charon overwrites
	// mmap'd .so files and SEGFAULTs it. The symlink is idempotent + always ensured.
	if !backend.StrongswanBundleReady() {
		if err := backend.ExtractStrongswanBundle(); err != nil {
			logger.Warning("charon: extract strongswan bundle:", err)
		}
	}
	if err := backend.LinkStrongswanIpsecDir(); err != nil {
		logger.Warning("charon: link strongswan ipsec dir:", err)
	}
	if !procMgr.IsRunning(ikev2ProcName) {
		_ = os.MkdirAll("/var/run", 0755)
		if err := procMgr.Start(ikev2ProcName, charonBin(), nil, nil, ikev2ConfigRoot); err != nil {
			return fmt.Errorf("start charon: %w", err)
		}
		if !waitForPath(viciSocket, 10*time.Second) {
			logger.Warning("charon: vici socket never appeared at", viciSocket)
		}
	}
	return nil
}

// reloadCharon (re)loads all swanctl conf.d connections/creds/pools into the running
// charon without dropping live SAs.
func reloadCharon() error {
	// Right after charon starts, its vici socket file can exist before charon actually
	// accepts connections (plugins still initializing), so a single --load-all can fail
	// with "Connection refused". On an ikev2+l2tp box the other protocol's later syncCharon
	// covers this, but an l2tp-only (or ikev2-only) box gets one shot, so retry briefly on
	// a vici connection error. A genuine config error (not a connect failure) breaks early.
	var out []byte
	var err error
	for attempt := 0; attempt < 6; attempt++ {
		out, err = exec.Command(swanctlBin(), "--load-all").CombinedOutput()
		if err == nil {
			return nil
		}
		s := string(out)
		if !strings.Contains(s, "Connection refused") && !strings.Contains(s, "connecting to") {
			break
		}
		time.Sleep(time.Second)
	}
	logger.Warning("charon: swanctl --load-all:", err, strings.TrimSpace(string(out)))
	return nil
}

// stopCharon stops the shared charon process.
func stopCharon() error {
	return procMgr.Stop(ikev2ProcName)
}

// syncCharon is the shared entrypoint both the ikev2 and l2tp services call after
// writing their own conf.d files. It starts (or stops) the one charon based on whether
// either protocol still needs it, and reloads all connections. Because it is keyed on the
// shared ikev2ProcName, ikev2 and l2tp cooperate: whichever runs last leaves charon in the
// right state, and `swanctl --load-all` merges both sets of conf.d files.
func syncCharon() error {
	if !charonNeeded() {
		return stopCharon()
	}
	if err := writeCharonConf(); err != nil {
		return err
	}
	if err := ensureCharonRunning(); err != nil {
		return err
	}
	return reloadCharon()
}
