package service

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// vpnKernelModules are the REQUIRED kernel modules the L2TP/PPTP/OpenVPN backends
// need. These are host/kernel-space and cannot be bundled into the binary — the
// setup/provision step ensures they are loaded and persisted.
var vpnKernelModules = []string{
	"ppp_generic",       // PPP core
	"l2tp_ppp",          // L2TP
	"nf_conntrack_pptp", // PPTP
	"ip_gre",            // PPTP/GRE
	"ppp_mppe",          // MPPE
	"nf_tproxy_ipv4",    // TPROXY (L2TP/PPTP/OpenVPN -> Xray)
	"tun",               // OpenVPN tun device
}

// vpnOptionalKernelModules are loaded when the running kernel ships them but are
// NOT required — their absence must not be flagged as a failure or trigger a
// kernel-modules install / reboot.
//
//   - af_key (PF_KEY): legacy IPsec key-management interface. Modern libreswan uses
//     the XFRM/netlink stack (built into the kernel, CONFIG_XFRM=y), not PF_KEY, and
//     RHEL 10 / Rocky 10 dropped the af_key module entirely — so IPsec works fine
//     without it. Loading it where present is harmless; its absence is expected.
//   - esp4 / xfrm_user: the ESP transform + netlink XFRM interface the bundled
//     strongSwan (IKEv2) drives through its kernel-netlink plugin — the SAME data-plane
//     the existing L2TP/IPsec (libreswan) path already uses, so it is present on every
//     validated target kernel (built-in, or a module the kernel autoloads on the first
//     SA). Preloading them best-effort just avoids relying on that on-demand autoload;
//     when they are built into the kernel there is no module to load and that is fine.
var vpnOptionalKernelModules = []string{
	"af_key",
	"esp4",
	"xfrm_user",
	// wireguard: the in-kernel WireGuard (C) data plane (mainline since Linux 5.6),
	// driven by wgctrl-go via netlink. Present on every validated target; optional so a
	// kernel without it degrades to a Warn (kernel-only build, no userspace fallback yet)
	// rather than failing provisioning. Autoloads on the first `ip link add type wireguard`.
	"wireguard",
	// amneziawg: the AmneziaWG data plane. Unlike every other entry here this module is
	// NOT shipped by any distro kernel; ensureAmneziawg DKMS-builds it from the vendored
	// source during setup. Listed so it shows up in the System card's module list once
	// built (GetSystemStatus only renders an optional module when it is actually
	// available, so it stays hidden rather than red on a host that never built it).
	//
	// It must stay OPTIONAL and out of vpnKernelModules: MissingKernelModules would
	// otherwise always report it (no stock kernel has it), sending provisionKernelModules
	// off to install a distro kernel package that cannot provide it and needlessly
	// tripping the reboot/bootloader-pin path.
	"amneziawg",
}

// CoreState is the coarse health of a backend "core".
type CoreState string

const (
	CoreRunning      CoreState = "running"       // daemon is up
	CoreStopped      CoreState = "stopped"       // installed + has inbounds, but not running
	CoreIdle         CoreState = "idle"          // installed but no inbounds configured
	CoreNotInstalled CoreState = "not_installed" // binary missing (needs setup/bundle)
	CoreError        CoreState = "error"         // running attempt failed
)

// CoreStatus is the status of a single backend core shown in the Core Settings panel.
type CoreStatus struct {
	Name     string         `json:"name"`     // xray | l2tp | pptp | openvpn | openconnect | radius
	State    CoreState      `json:"state"`    //
	Detail   string         `json:"detail"`   // human-readable extra info / error
	Version  string         `json:"version"`  // where available (xray)
	Inbounds int            `json:"inbounds"` // number of inbounds of this type
	Extra    map[string]any `json:"extra,omitempty"`
}

// ModuleStatus reports whether a kernel module is loaded. Optional modules (e.g.
// af_key on kernels that dropped PF_KEY) don't count against readiness.
type ModuleStatus struct {
	Name     string `json:"name"`
	Loaded   bool   `json:"loaded"`
	Optional bool   `json:"optional,omitempty"`
}

// SystemStatus reports the host/kernel prerequisites that can't be baked into
// the binary — exactly the things the setup script used to worry about.
type SystemStatus struct {
	IpForward bool           `json:"ipForward"`
	Nftables  bool           `json:"nftables"`
	Iproute   bool           `json:"iproute"`
	Modules   []ModuleStatus `json:"modules"`
	ModulesOK bool           `json:"modulesOk"`
}

// ProvisionStep is one action taken by Provision(), for reporting to the UI/CLI.
// Warn marks a step that succeeded but needs the operator's attention (e.g. a
// kernel package was installed but its modules only load after a reboot). Log
// holds the raw command output for that step (package-manager output, modprobe
// errors, …), shown when the operator expands the step in the setup console.
type ProvisionStep struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Warn bool   `json:"warn,omitempty"`
	Msg  string `json:"msg"`
	Log  string `json:"log,omitempty"`
}

// CoreService aggregates status and provisioning across all backend cores.
// Like the other services it is a zero-value-usable value type; its methods are
// stateless (they read the DB and probe the host), so a fresh copy works.
type CoreService struct {
	l2tpService    L2tpService
	pptpService    PptpService
	openvpnService OpenVpnService
	ocservService  OcservService
	sstpService    SstpService
	ikev2Service   Ikev2Service
	wgcService     WgcService
	awgService     AwgService
	greService     GreService
	mtprotoService MtprotoService
	sshService     SshService
	xrayService    XrayService
}

// --------------------------------------------------------------------------- //
//  Host probes
// --------------------------------------------------------------------------- //

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// daemonInstalled reports whether a daemon is available either from the host
// (in PATH) or from the bundle baked into the binary and extracted at setup.
func daemonInstalled(name string) bool {
	return commandExists(name) || backend.DaemonPath(name) != ""
}

func systemctlActive(unit string) bool {
	if !commandExists("systemctl") {
		return false
	}
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}

func moduleLoaded(name string) bool {
	// A loaded module has /sys/module/<name>. A built-in module ALSO has that entry
	// — but ONLY if it exports at least one module parameter; a param-less built-in
	// (e.g. `tun`) has no /sys/module entry at all, so /sys alone false-negatives on
	// it and it would show "not loaded"/red even though it's compiled into the kernel
	// and always available. Fall back to the kernel's modules.builtin list for those.
	if _, err := os.Stat("/sys/module/" + name); err == nil {
		return true
	}
	return moduleBuiltin(name)
}

// moduleBuiltin reports whether the module is compiled into the running kernel,
// per /lib/modules/<ver>/modules.builtin (which lists built-in modules as
// "kernel/.../<name>.ko" paths). Built-ins are always available and need no load.
func moduleBuiltin(name string) bool {
	data, err := os.ReadFile("/lib/modules/" + runningKernel() + "/modules.builtin")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "/"+name+".ko")
}

// moduleAvailable reports whether a module can be used on the running kernel —
// already loaded, built into the kernel, or loadable on demand. It drives the
// "do we need to install a kernel package?" decision, so it must NOT false-
// negative on built-in modules (which have no /sys/module entry): `modprobe -nq`
// resolves both loadable .ko files and built-ins, returning success for either.
func moduleAvailable(name string) bool {
	if moduleLoaded(name) {
		return true
	}
	return exec.Command("modprobe", "-nq", name).Run() == nil
}

var (
	daemonVersionRe    = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)
	daemonVersionCache = map[string]string{}
	daemonVersionMu    sync.Mutex
)

// daemonVersion returns a short version string (e.g. "2.6.12") for a bundled or
// host daemon by running `<bin> --version` and grabbing the first version-shaped
// token. Output is read regardless of exit code (some daemons exit non-zero on
// --version). Successful lookups are cached; "" is returned (and not cached) when
// the daemon isn't available, so it retries once it's installed.
func daemonVersion(name string) string {
	daemonVersionMu.Lock()
	if v, ok := daemonVersionCache[name]; ok {
		daemonVersionMu.Unlock()
		return v
	}
	daemonVersionMu.Unlock()

	bin := ""
	if p := backend.DaemonPath(name); p != "" {
		bin = p
	} else if p := backend.AccelBinPath(name); p != "" {
		// accel-ppp (SSTP) ships as a relocatable tree bundle, not a flat BinDir
		// binary, so its launchers resolve here — mirrors daemonBin().
		bin = p
	} else if p := backend.StrongswanBinPath(name); p != "" {
		// strongSwan (IKEv2) also ships as a relocatable tree bundle, so the bundled
		// charon launcher resolves here — otherwise `charon --version` (a "strongSwan
		// 5.9.14" line) is never run and the IKEv2 core version shows as "—".
		bin = p
	} else if p, err := exec.LookPath(name); err == nil {
		bin = p
	} else {
		return ""
	}
	out, _ := exec.Command(bin, "--version").CombinedOutput()
	v := daemonVersionRe.FindString(string(out))
	if v != "" {
		daemonVersionMu.Lock()
		daemonVersionCache[name] = v
		daemonVersionMu.Unlock()
	}
	return v
}

func procFileIsOne(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == "1"
}

// --------------------------------------------------------------------------- //
//  Per-core status
// --------------------------------------------------------------------------- //

// dokodemoPortBound reports whether something is already listening on the given
// TCP port — i.e. Xray bound its dokodemo-door for a VPN inbound. Probes by
// trying to bind: bind fails (address in use) → taken; bind succeeds → the port
// is free, meaning Xray failed to bind it.
func dokodemoPortBound(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// MissingDokodemoPorts returns the TPROXY/dokodemo ports that SHOULD be bound —
// one per enabled L2TP/PPTP/OpenVPN inbound, since that's how their traffic
// reaches Xray — but currently are not. A non-empty result means Xray silently
// failed to bind them on a restart, so those VPNs have no internet until it
// rebinds. Consumed by CheckVpnDokodemoJob to self-heal.
func (s *CoreService) MissingDokodemoPorts() []int {
	var missing []int
	if ins, err := s.l2tpService.GetL2tpInbounds(); err == nil {
		for _, in := range ins {
			if port := s.l2tpService.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.pptpService.GetPptpInbounds(); err == nil {
		for _, in := range ins {
			if port := s.pptpService.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.openvpnService.GetOpenVpnInbounds(); err == nil {
		for _, in := range ins {
			// One shared dokodemo per OpenVPN inbound (both transports use it).
			if port := s.openvpnService.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.ocservService.GetOcservInbounds(); err == nil {
		for _, in := range ins {
			if port := s.ocservService.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.sstpService.GetSstpInbounds(); err == nil {
		for _, in := range ins {
			if port := s.sstpService.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	if ins, err := s.ikev2Service.GetIkev2Inbounds(); err == nil {
		for _, in := range ins {
			if port := s.ikev2Service.GetTproxyPort(in); in.Enable && !dokodemoPortBound(port) {
				missing = append(missing, port)
			}
		}
	}
	return missing
}

// GetCoresStatus returns the status of every backend core, in display order.
func (s *CoreService) GetCoresStatus() []CoreStatus {
	all := []CoreStatus{
		s.xrayStatus(),
		s.l2tpStatus(),
		s.ipsecStatus(),
		s.pptpStatus(),
		s.openvpnStatus(),
		s.ocservStatus(),
		s.sstpStatus(),
		s.ikev2Status(),
		s.wgcStatus(),
		s.awgStatus(),
		s.greStatus(),
		s.mtprotoStatus(),
		s.sshStatus(),
		s.radiusStatus(),
	}

	// A core the operator never installed reads as "not installed", whatever the
	// host probes say. Several cores would otherwise report themselves ready off
	// an embedded bundle (strongSwan, accel-ppp) or a stock kernel module
	// (WireGuard) that setup has not actually wired up on this host.
	installed := s.provisionedProtocolSet()
	installedNames := coreNamesFromSet(installed)
	for i := range all {
		if coreInstalled(all[i].Name, installed, installedNames) {
			continue
		}
		all[i].State = CoreNotInstalled
		all[i].Version = ""
		if all[i].Detail == "" {
			all[i].Detail = "not installed on this host"
		}
	}
	return all
}

// coreInstalled answers "has this host been set up for this core" for each of the
// three shapes of core the status cards show.
//
//   - A catalog core the operator picks: the recorded set is the only answer.
//   - A DERIVED core (ipsec, radius): nobody installs it directly, it exists only
//     to serve other cores, so it is installed exactly when an installed core
//     needs it. That is reference counting against what IS installed, the same
//     arithmetic uninstall runs against what REMAINS.
//   - A built-in core nothing else depends on (xray, ssh): part of the panel, so
//     it is always installed and its card reports plain liveness.
//
// ipsec and radius used to skip this check and fall through to their own probes,
// and on a host that has installed nothing both probes lie. The strongSwan bundle
// is embedded in the binary whether or not setup ever extracted it, so ipsec read
// "stopped"; the in-binary RADIUS server binds :1812 from panel start, so radius
// read "running" with nothing on the host for it to authenticate.
func coreInstalled(name string, installed map[string]bool, installedNames []string) bool {
	switch name {
	case "ipsec":
		// The shared IPsec layer: one charon serving L2TP/IPsec and IKEv2, or host
		// libreswan on an arch with no bundle. Only those two claim featStrongswan,
		// so a host with neither has no IPsec to report on.
		return needsFeature(installedNames, featStrongswan)
	case "radius":
		return anyCoreUsesRadius(installedNames)
	}
	spec := coreSpecFor(name)
	if spec == nil {
		return false
	}
	return spec.builtin || installed[name]
}

// xrayServedProtocols are the protocols the Overview lists as services of their
// own even though no daemon of theirs exists: one Xray process serves all of
// them, so their health IS Xray's health, qualified by whether an inbound of that
// protocol has been configured at all.
//
// They are deliberately NOT cores. A core is something the operator installs,
// starts and stops (see corecatalog.go), and none of that is true here - a card on
// the Core Settings page offering to stop AnyTLS would be offering to stop
// something that does not exist as a process.
var xrayServedProtocols = []string{"anytls", "tuic", "naive"}

// xrayProtocolInbounds counts the inbounds of each Xray-served protocol, so the
// Overview can tell "serving accounts" from "available but unused" without
// fetching the whole inbound list into a page that lists no inbounds.
func xrayProtocolInbounds() map[string]any {
	out := make(map[string]any, len(xrayServedProtocols))
	for _, p := range xrayServedProtocols {
		out[p] = 0
	}
	db := database.GetDB()
	if db == nil {
		return out
	}
	var rows []struct {
		Protocol string
		N        int
	}
	if err := db.Model(model.Inbound{}).
		Select("protocol, count(*) as n").
		Where("protocol IN (?) AND enable = ?", xrayServedProtocols, true).
		Group("protocol").Scan(&rows).Error; err != nil {
		logger.Warning("counting Xray-served protocol inbounds: ", err)
		return out
	}
	for _, r := range rows {
		out[r.Protocol] = r.N
	}
	return out
}

func (s *CoreService) xrayStatus() CoreStatus {
	cs := CoreStatus{Name: "xray"}
	// Carried on the Xray status rather than as statuses of their own: these
	// protocols have no separate process to report on, and inventing a core for
	// each would put a start/stop card on the Core Settings page for something
	// with nothing to start.
	cs.Extra = map[string]any{"protocolInbounds": xrayProtocolInbounds()}
	if s.xrayService.IsXrayRunning() {
		cs.State = CoreRunning
		cs.Version = s.xrayService.GetXrayVersion()
		return cs
	}
	if err := s.xrayService.GetXrayErr(); err != nil {
		cs.State = CoreError
		cs.Detail = err.Error()
		return cs
	}
	cs.State = CoreStopped
	return cs
}

func (s *CoreService) l2tpStatus() CoreStatus {
	cs := CoreStatus{Name: "l2tp"}
	inbounds, _ := s.l2tpService.GetL2tpInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("xl2tpd") {
		cs.State = CoreNotInstalled
		cs.Detail = "xl2tpd not installed"
		return cs
	}
	cs.Version = daemonVersion("xl2tpd")
	switch {
	case procMgr.IsRunning("xl2tpd"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

// ipsecStatus reports libreswan (IPsec) as its own core. It runs either as our
// bundled USE_DH2 pluto (a supervised procMgr child, when a bundle is embedded)
// or as the host's ipsec.service — either way it underpins L2TP/IPsec but
// installs, versions and runs independently of xl2tpd, so it gets its own card.
func (s *CoreService) ipsecStatus() CoreStatus {
	cs := CoreStatus{Name: "ipsec"}
	// Bundled-strongSwan path (amd64): L2TP/IPsec is served by the SAME charon as IKEv2
	// (one daemon on UDP 500/4500). Report the charon process + strongSwan version so this
	// core reflects reality instead of the retired libreswan/pluto. Note for the UI: ipsec
	// and ikev2 now share one daemon, so stopping one stops both.
	if backend.HasStrongswanBundle() {
		if v := daemonVersion("charon"); v != "" {
			cs.Version = v
		}
		switch {
		case procMgr.IsRunning(ikev2ProcName):
			cs.State = CoreRunning
		case !charonNeeded():
			// No enabled inbound wants IPsec (no IKEv2, and no L2TP or GRE with
			// ipsecEnable), so charon is MEANT to be down. "Idle" says that; amber
			// "Stopped" reads as a fault the operator is supposed to go and fix.
			cs.State = CoreIdle
		default:
			cs.State = CoreStopped
		}
		return cs
	}
	// Host libreswan path (arches without the strongSwan bundle).
	if !ipsecAvailable() {
		cs.State = CoreNotInstalled
		cs.Detail = "libreswan (ipsec) not installed"
		return cs
	}
	if maj, min, ok := libreswanVersion(); ok {
		cs.Version = fmt.Sprintf("%d.%d", maj, min)
	}
	running := systemctlActive("ipsec")
	if usingBundledIpsec() {
		running = bundledPlutoRunning()
	}
	if running {
		cs.State = CoreRunning
	} else {
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) pptpStatus() CoreStatus {
	cs := CoreStatus{Name: "pptp"}
	inbounds, _ := s.pptpService.GetPptpInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("pptpd") {
		cs.State = CoreNotInstalled
		cs.Detail = "pptpd not installed"
		return cs
	}
	cs.Version = daemonVersion("pptpd")
	switch {
	case procMgr.IsRunning("pptpd"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) openvpnStatus() CoreStatus {
	cs := CoreStatus{Name: "openvpn"}
	inbounds, _ := s.openvpnService.GetOpenVpnInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("openvpn") {
		cs.State = CoreNotInstalled
		cs.Detail = "openvpn not installed"
		return cs
	}
	cs.Version = daemonVersion("openvpn")
	switch {
	case procMgr.AnyRunningWithPrefix("openvpn-server-"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) ocservStatus() CoreStatus {
	cs := CoreStatus{Name: "openconnect"}
	inbounds, _ := s.ocservService.GetOcservInbounds()
	cs.Inbounds = len(inbounds)
	if !daemonInstalled("ocserv") {
		cs.State = CoreNotInstalled
		cs.Detail = "ocserv not installed"
		return cs
	}
	cs.Version = daemonVersion("ocserv")
	switch {
	case procMgr.AnyRunningWithPrefix("ocserv-server-"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) sstpStatus() CoreStatus {
	cs := CoreStatus{Name: "sstp"}
	inbounds, _ := s.sstpService.GetSstpInbounds()
	cs.Inbounds = len(inbounds)
	// accel-pppd ships as a relocatable TREE bundle (not a flat BinDir daemon), so
	// daemonInstalled — which only consults PATH + backend.DaemonPath — misses it;
	// HasAccelBundle covers the baked-in-binary case. Either presence = installed.
	if !daemonInstalled("accel-pppd") && !backend.HasAccelBundle() {
		cs.State = CoreNotInstalled
		cs.Detail = "accel-ppp (accel-pppd) not installed"
		return cs
	}
	cs.Version = daemonVersion("accel-pppd")
	switch {
	case procMgr.AnyRunningWithPrefix("sstp-server-"):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) ikev2Status() CoreStatus {
	cs := CoreStatus{Name: "ikev2"}
	inbounds, _ := s.ikev2Service.GetIkev2Inbounds()
	cs.Inbounds = len(inbounds)
	// charon ships as a relocatable TREE bundle (not a flat BinDir daemon), so
	// daemonInstalled (PATH + backend.DaemonPath only) misses it; HasStrongswanBundle
	// covers the baked-in-binary case. Either presence = installed.
	if !daemonInstalled("charon") && !backend.HasStrongswanBundle() {
		cs.State = CoreNotInstalled
		cs.Detail = "strongSwan (charon) not installed"
		return cs
	}
	cs.Version = daemonVersion("charon")
	switch {
	case procMgr.IsRunning(ikev2ProcName):
		cs.State = CoreRunning
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	default:
		cs.State = CoreStopped
	}
	return cs
}

// wgcStatus reports the WireGuard (C) core. Unlike the daemon-backed protocols there
// is no process to check: the data plane is the in-kernel wireguard module + the panel's
// wgctrl-managed interfaces. State is module-availability + interface presence based.
func (s *CoreService) wgcStatus() CoreStatus {
	cs := CoreStatus{Name: "wgc"}
	inbounds, _ := s.wgcService.GetWgcInbounds()
	cs.Inbounds = len(inbounds)
	if !s.wgcService.WireguardAvailable() {
		cs.State = CoreNotInstalled
		cs.Detail = "wireguard kernel module not available"
		return cs
	}
	cs.Version = wireguardModuleVersion()
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case s.wgcService.AnyInterfaceUp():
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

// greStatus reports the GRE core. Like wg-c and awg it has no daemon: the data plane is the
// in-tree ip_gre module plus the netdevs GreService reconciles over netlink. ip_gre is
// frequently compiled into the kernel rather than built as a module, so availability is
// probed via the fallback device the driver registers, not only via /sys/module.
func (s *CoreService) greStatus() CoreStatus {
	cs := CoreStatus{Name: "gre"}
	inbounds, _ := s.greService.GetGreInbounds()
	cs.Inbounds = len(inbounds)
	if !s.greService.GreAvailable() {
		cs.State = CoreNotInstalled
		cs.Detail = "kernel GRE (ip_gre) not available (run Core Settings setup)"
		return cs
	}
	cs.Version = "kernel"
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case s.greService.AnyInterfaceUp():
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

// awgStatus reports the AmneziaWG core. Like wg-c it has no daemon: the data plane is the
// out-of-tree amneziawg kernel module (DKMS-built) + the panel's wgctrl-managed interfaces.
func (s *CoreService) awgStatus() CoreStatus {
	cs := CoreStatus{Name: "awg"}
	inbounds, _ := s.awgService.GetAwgInbounds()
	cs.Inbounds = len(inbounds)
	if !s.awgService.AmneziawgAvailable() {
		cs.State = CoreNotInstalled
		// Distinguish "setup has not run yet" from "this host cannot build it at all".
		// Telling an operator on Fedora/Arch/RHEL to re-run setup would send them round a
		// loop that can never succeed, so say what is actually wrong.
		if ok, why := awgKernelModuleSupported(); !ok {
			cs.Detail = why
		} else {
			cs.Detail = "amneziawg kernel module not built (run Core Settings setup)"
		}
		return cs
	}
	cs.Version = amneziawgModuleVersion()
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case s.awgService.AnyInterfaceUp():
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

// mtprotoStatus reports the MTProto Proxy core. Unlike the tunnel protocols there
// is no kernel module or interface to probe: telemt is a plain userspace relay, so
// availability is just "is the bundled binary present" and liveness is "is any
// per-inbound child running".
func (s *CoreService) mtprotoStatus() CoreStatus {
	cs := CoreStatus{Name: "mtproto"}
	inbounds, _ := s.mtprotoService.GetMtprotoInbounds()
	cs.Inbounds = len(inbounds)
	if !s.mtprotoService.Available() {
		cs.State = CoreNotInstalled
		cs.Detail = "telemt binary not bundled for this architecture"
		return cs
	}
	cs.Version = daemonVersion("telemt")
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case procMgr.AnyRunningWithPrefix("mtproto-server-"):
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

func (s *CoreService) radiusStatus() CoreStatus {
	cs := CoreStatus{Name: "radius"}
	// RADIUS is embedded in the panel binary, so its version is the panel's.
	cs.Version = config.GetVersion()
	// The embedded RADIUS server binds 127.0.0.1:1812 (auth). If the port can't
	// be bound, the server is already listening — which is what we want.
	pc, err := net.ListenPacket("udp", "127.0.0.1:1812")
	if err != nil {
		cs.State = CoreRunning
		return cs
	}
	_ = pc.Close()
	cs.State = CoreStopped
	return cs
}

// sshStatus reports the SSH core. Like radius/wgc it is an in-binary Go server, so it
// is always "installed" (no bundled binary, no host dependency); "running" means at
// least one SSH listener is bound.
func (s *CoreService) sshStatus() CoreStatus {
	cs := CoreStatus{Name: "ssh"}
	cs.Version = config.GetVersion()
	inbounds, _ := s.sshService.GetSshInbounds()
	cs.Inbounds = len(inbounds)
	switch {
	case cs.Inbounds == 0:
		cs.State = CoreIdle
	case s.sshService.AnyRunning():
		cs.State = CoreRunning
	default:
		cs.State = CoreStopped
	}
	return cs
}

// --------------------------------------------------------------------------- //
//  System / kernel status
// --------------------------------------------------------------------------- //

// GetSystemStatus reports the host prerequisites (kernel modules, ip_forward,
// nftables) that cannot be baked into the binary.
func (s *CoreService) GetSystemStatus() SystemStatus {
	st := SystemStatus{
		IpForward: procFileIsOne("/proc/sys/net/ipv4/ip_forward"),
		Nftables:  commandExists("nft"),
		Iproute:   commandExists("ip"),
		ModulesOK: true,
	}
	// Scoped to the installed cores: a module belonging to a core this host never
	// installed is not missing, it is irrelevant, and reporting it red would ask
	// the operator to fix something they deliberately did not ask for.
	installed := s.installedCoreNames()
	for _, m := range requiredModulesFor(installed) {
		loaded := moduleLoaded(m)
		if !loaded {
			st.ModulesOK = false
		}
		st.Modules = append(st.Modules, ModuleStatus{Name: m, Loaded: loaded})
	}
	// Optional modules are shown only when the running kernel actually ships them,
	// so a module the kernel dropped (af_key on RHEL 10+) doesn't surface as a red
	// "not loaded" row or drag ModulesOK down.
	for _, m := range optionalModulesFor(installed) {
		if moduleAvailable(m) {
			st.Modules = append(st.Modules, ModuleStatus{Name: m, Loaded: moduleLoaded(m), Optional: true})
		}
	}
	return st
}

// IsProvisioned reports whether the VPN backend setup ("Initialize Setup") has
// been completed. It is true when the persisted flag is set, or — for installs
// provisioned before that flag existed — when the host already looks prepared:
// IP forwarding is enabled and a bundled daemon is available (daemons are only
// extracted by Provision). This fallback keeps already-set-up upgrades from
// regressing to the setup call-to-action.
func (s *CoreService) IsProvisioned() bool {
	var ss SettingService
	if ss.GetVpnProvisioned() {
		return true
	}
	return procFileIsOne("/proc/sys/net/ipv4/ip_forward") && daemonInstalled("openvpn")
}

// provisionBaseline is FROZEN: the protocol set as of when per-protocol setup
// tracking was introduced. Do NOT add to it. It credits pre-tracking installs
// (vpnProvisioned=true, no recorded list) with the protocols that already
// existed, so an upgrade is not wrongly told every protocol is new.
var provisionBaseline = []string{"l2tp", "pptp", "openvpn", "openconnect"}

// provisionedProtocolSet returns the cores the host has been set up for. Setup
// is per-core now, so this is the authoritative "is it installed" answer for
// everything downstream: the status cards, the inbound-creation gate, and the
// shared-requirement arithmetic that decides what an uninstall may remove.
func (s *CoreService) provisionedProtocolSet() map[string]bool {
	var ss SettingService
	set := map[string]bool{}
	if list := ss.GetProvisionedProtocols(); len(list) > 0 {
		for _, p := range list {
			set[p] = true
		}
		return set
	}
	// An install that has recorded its core set and recorded it as EMPTY is
	// authoritative: the operator uninstalled everything. Falling through to the
	// baseline here would resurrect the original four cores as "installed" the
	// moment the last one was removed.
	if ss.HasRecordedProvisionedProtocols() {
		return set
	}
	// No recorded list but the host looks provisioned: a pre-tracking install.
	// Credit the frozen baseline, which is what its setup run actually covered.
	if s.IsProvisioned() {
		for _, p := range provisionBaseline {
			set[p] = true
		}
	}
	return set
}

// MissingProtocols returns installable cores this host is NOT set up for. Since
// setup became per-core these are cores the operator has not installed (or has
// uninstalled), not a defect: the Core Settings page offers them under "Add
// core" rather than nagging about them.
func (s *CoreService) MissingProtocols() []string {
	if !s.IsProvisioned() {
		return nil
	}
	provisioned := s.provisionedProtocolSet()
	var missing []string
	for _, p := range installableCores() {
		if !provisioned[p] {
			missing = append(missing, p)
		}
	}
	return missing
}

// ProtocolNeedsSetup reports whether an inbound protocol's core still has to be
// installed before it can serve anything. Xray-native protocols map to no core
// and are never gated.
func (s *CoreService) ProtocolNeedsSetup(protocol string) bool {
	core := protocolCoreName(protocol)
	if core == "" {
		return false
	}
	return !s.provisionedProtocolSet()[core]
}

// --------------------------------------------------------------------------- //
//  Control + provisioning
// --------------------------------------------------------------------------- //

// RestartCore restarts the daemon(s) for a given core.
func (s *CoreService) RestartCore(name string) error {
	switch name {
	case "xray":
		return s.xrayService.RestartXray(true)
	case "l2tp":
		return s.l2tpService.RestartServices()
	case "pptp":
		return s.pptpService.RestartServices()
	case "openvpn":
		return s.openvpnService.RestartServices()
	case "openconnect":
		return s.ocservService.RestartServices()
	case "sstp":
		return s.sstpService.RestartServices()
	case "ikev2":
		return s.ikev2Service.RestartServices()
	case "wgc":
		return s.wgcService.RestartServices()
	case "awg":
		return s.awgService.RestartServices()
	case "gre":
		return s.greService.RestartServices()
	case "mtproto":
		return s.mtprotoService.RestartServices()
	case "ssh":
		return s.sshService.RestartServices()
	case "radius":
		return RestartRadius()
	case "ipsec":
		_, err := restartIpsecService()
		return err
	default:
		return fmt.Errorf("unknown core: %s", name)
	}
}

// RestartAll restarts every core in a sensible order, aggregating any errors so
// one failing core doesn't abort the rest.
func (s *CoreService) RestartAll() error {
	var errs []string
	for _, name := range []string{"xray", "l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "wgc", "awg", "gre", "mtproto", "ssh", "radius"} {
		if err := s.RestartCore(name); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// StopCore stops a core, where stopping is supported.
func (s *CoreService) StopCore(name string) error {
	switch name {
	case "xray":
		return s.xrayService.StopXray()
	case "l2tp":
		s.l2tpService.StopServices()
		return nil
	case "pptp":
		s.pptpService.StopServices()
		return nil
	case "openvpn":
		s.openvpnService.StopServices()
		return nil
	case "openconnect":
		s.ocservService.StopServices()
		return nil
	case "sstp":
		s.sstpService.StopServices()
		return nil
	case "ikev2":
		return s.ikev2Service.StopServices()
	case "wgc":
		return s.wgcService.StopServices()
	case "awg":
		return s.awgService.StopServices()
	case "gre":
		return s.greService.StopServices()
	case "mtproto":
		return s.mtprotoService.StopServices()
	case "ssh":
		return s.sshService.StopServices()
	case "radius":
		return StopRadius()
	case "ipsec":
		return stopIpsecService()
	default:
		return fmt.Errorf("core %s does not support stop", name)
	}
}

// CoreLogs returns recent captured output for a core. VPN daemons return their
// supervised child-process output; xray/radius return the matching lines from
// the panel's in-memory log buffer (their output is routed there).
func (s *CoreService) CoreLogs(name string) string {
	switch name {
	case "l2tp":
		return procMgr.Logs("xl2tpd")
	case "pptp":
		return procMgr.Logs("pptpd")
	case "openvpn":
		return procMgr.LogsByPrefix("openvpn-server-")
	case "openconnect":
		return procMgr.LogsByPrefix("ocserv-server-")
	case "sstp":
		return procMgr.LogsByPrefix("sstp-server-")
	case "ikev2":
		return procMgr.Logs(ikev2ProcName)
	case "wgc":
		if !s.wgcService.WireguardAvailable() {
			return "WireGuard (C): kernel module 'wireguard' not available on this host."
		}
		up := "no"
		if s.wgcService.AnyInterfaceUp() {
			up = "yes"
		}
		return fmt.Sprintf("WireGuard (C) runs in-kernel via wgctrl (no daemon log).\nModule version: %s\nInterface(s) up: %s", wireguardModuleVersion(), up)
	case "awg":
		if !s.awgService.AmneziawgAvailable() {
			return "AmneziaWG: kernel module 'amneziawg' not built on this host (run Core Settings setup)."
		}
		up := "no"
		if s.awgService.AnyInterfaceUp() {
			up = "yes"
		}
		return fmt.Sprintf("AmneziaWG runs in-kernel via the wgctrl fork (no daemon log).\nModule version: %s\nInterface(s) up: %s", amneziawgModuleVersion(), up)
	case "gre":
		if !s.greService.GreAvailable() {
			return "GRE: kernel GRE (ip_gre) not available on this host."
		}
		up := "no"
		if s.greService.AnyInterfaceUp() {
			up = "yes"
		}
		fou := "no"
		if s.greService.FouAvailable() {
			fou = "yes"
		}
		return fmt.Sprintf("GRE runs in-kernel via netlink (no daemon log).\nTunnel(s) up: %s\nFOU (UDP encap) available: %s", up, fou)
	case "mtproto":
		return procMgr.LogsByPrefix("mtproto-server-")
	case "ssh":
		running := "no"
		if s.sshService.AnyRunning() {
			running = "yes"
		}
		return fmt.Sprintf("SSH gateway runs in-binary (no daemon log).\nListener(s) bound: %s\n\n%s", running, filterLogs("SSH:"))
	case "xray":
		out := filterLogs("xray")
		if out == "" {
			return s.xrayService.GetXrayResult()
		}
		return out
	case "radius":
		return filterLogs("radius")
	case "ipsec":
		return ipsecFailureDiagnostics()
	}
	return ""
}

// filterLogs returns the most recent panel log lines (chronological) whose text
// mentions the given keyword (case-insensitive).
func filterLogs(keyword string) string {
	lines := logger.GetLogs(400, "debug")
	kw := strings.ToLower(keyword)
	var matched []string
	// GetLogs returns newest-first; walk backwards to emit chronological order.
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(strings.ToLower(lines[i]), kw) {
			matched = append(matched, lines[i])
		}
	}
	return strings.Join(matched, "\n")
}

// Provision performs the host/kernel preparation that no bundled binary can do:
// load + persist the required kernel modules and enable + persist IP forwarding.
// It is idempotent and safe to run repeatedly. This is the in-binary replacement
// for the legacy host-prep shell script. It collects and returns all
// steps; use StartProvision for the streamed, non-blocking variant.
//
// cores selects which VPN cores to provision for; a nil/empty selection means
// every installable core, which is what the CLI and the legacy all-in-one setup
// path want.
func (s *CoreService) Provision(cores []string) []ProvisionStep {
	var steps []ProvisionStep
	s.runProvisionSteps(func(st ProvisionStep) { steps = append(steps, st) }, cores)
	return steps
}

// runProvisionSteps performs each provisioning action and invokes emit after
// every step, so callers can stream progress to a live log. It is idempotent.
// It returns the kernel modules that will only load after a reboot (empty when
// none) together with the package that provides them, so the caller can prompt
// the operator to reboot.
//
// `cores` scopes the run, along two axes that are deliberately different.
//
//   - The WORK is scoped to the selection. Host-wide steps (forwarding,
//     rp_filter, firewalld, nftables, iproute2) always run because they are the
//     data plane every core shares, but the expensive per-core features (the
//     pppd / accel-ppp / strongSwan bundles, the kernel-modules package, the
//     AmneziaWG build) run only for the cores being installed. Adding one core
//     therefore does not re-extract every bundle an already-installed core owns.
//   - The PERSISTED STATE is scoped to the union of the selection and what is
//     already installed, so "install WireGuard" cannot quietly un-persist L2TP's
//     kernel modules or delete its daemon binaries.
//
// Re-run Setup is what repairs an existing core: it passes the installed set as
// the selection, which puts both axes back together.
func (s *CoreService) runProvisionSteps(emit func(ProvisionStep), cores []string) (rebootModules []string, rebootPkg string) {
	selected := cores
	if len(selected) == 0 {
		selected = installableCores()
	}
	target := dedupe(append(append([]string{}, s.installedCoreNames()...), selected...))

	requiredModules := requiredModulesFor(target)
	optionalModules := optionalModulesFor(target)

	for _, m := range requiredModules {
		if moduleLoaded(m) {
			emit(ProvisionStep{Name: "module " + m, OK: true, Msg: "already loaded"})
			continue
		}
		out, err := exec.Command("modprobe", m).CombinedOutput()
		if err == nil {
			emit(ProvisionStep{Name: "modprobe " + m, OK: true, Msg: "loaded"})
		} else {
			// Not present in the running kernel. Expected on minimal/cloud images;
			// the kernel-modules step below installs it (rebooting into a fuller
			// kernel when the module only ships there). Flag as a warning, not an
			// error, so the console doesn't look broken mid-run.
			emit(ProvisionStep{Name: "modprobe " + m, OK: true, Warn: true,
				Msg: "not in the running kernel — resolving below", Log: strings.TrimSpace(string(out))})
		}
	}

	// Optional modules: load where the kernel ships them; a kernel that dropped one
	// (af_key on RHEL 10+) is fine — IPsec uses XFRM — so report it as OK info, not
	// a failure, and never let it drive the kernel-modules install/reboot below.
	var loadableOptional []string
	for _, m := range optionalModules {
		if moduleLoaded(m) {
			loadableOptional = append(loadableOptional, m)
			emit(ProvisionStep{Name: "module " + m, OK: true, Msg: "already loaded (optional)"})
			continue
		}
		if !moduleAvailable(m) {
			// amneziawg is the one entry here that no kernel ships: it is built from the
			// vendored source by ensureAmneziawg later in THIS same pass, so on a first
			// run it is legitimately absent at this point. Saying "IPsec uses XFRM
			// instead" would be simply wrong for it.
			msg := "not on this kernel, optional: IPsec uses XFRM instead"
			if m == amneziawgModule {
				// Deliberately neutral: on a supported host the AmneziaWG step below builds
				// it, on an unsupported one that step explains why it cannot. Promising a
				// build here would contradict the very next line on Fedora/Arch/RHEL.
				msg = "not built yet, see the AmneziaWG step below"
			}
			emit(ProvisionStep{Name: "module " + m, OK: true, Msg: msg})
			continue
		}
		if exec.Command("modprobe", m).Run() == nil {
			loadableOptional = append(loadableOptional, m)
			emit(ProvisionStep{Name: "modprobe " + m, OK: true, Msg: "loaded (optional)"})
		}
	}

	// Persist only the modules present on this kernel, so systemd-modules-load
	// doesn't log a failure each boot for an optional module the kernel dropped.
	modConf := strings.Join(append(append([]string{}, requiredModules...), loadableOptional...), "\n") + "\n"
	err := os.WriteFile("/etc/modules-load.d/vpn-ui.conf", []byte(modConf), 0644)
	emit(ProvisionStep{Name: "persist /etc/modules-load.d/vpn-ui.conf", OK: err == nil, Msg: msgOrOK(err)})

	err = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	emit(ProvisionStep{Name: "sysctl net.ipv4.ip_forward=1", OK: err == nil, Msg: msgOrOK(err)})

	// Persist ip_forward plus loose rp_filter. Fedora/RHEL default rp_filter to
	// strict (1), which drops the policy-routed TPROXY packets carrying VPN client
	// traffic into Xray; loose (2, Ubuntu's default) fixes it. This 99-*.conf sorts
	// after Fedora's 50-default.conf, so it wins on boot.
	const sysctlConf = "net.ipv4.ip_forward=1\n" +
		"net.ipv4.conf.all.rp_filter=2\n" +
		"net.ipv4.conf.default.rp_filter=2\n"
	err = os.WriteFile("/etc/sysctl.d/99-vpn-ui.conf", []byte(sysctlConf), 0644)
	emit(ProvisionStep{Name: "persist /etc/sysctl.d/99-vpn-ui.conf", OK: err == nil, Msg: msgOrOK(err)})

	// Apply loose rp_filter now and, when firewalld is active (Fedora/RHEL), trust
	// the VPN address space so its default-drop INPUT policy doesn't block the
	// TPROXY'd data plane. No-op on Debian/Ubuntu.
	ensureVpnHostNetworking()
	emit(ProvisionStep{Name: "relax rp_filter + trust VPN in firewalld", OK: true, Msg: firewallStepMsg()})

	// Extract the daemons baked into the binary and generate their systemd units.
	// On a build without an embedded bundle this is a no-op.
	//
	// Only the selected cores' binaries are written: "installed" is decided by the
	// binary being present (daemonInstalled), so extracting the whole bundle would
	// report every core installed however few the operator picked.
	if backend.Available() {
		wanted := daemonsFor(target)
		files, exErr := backend.ExtractOnly(wanted)
		emit(ProvisionStep{Name: "extract bundled daemons", OK: exErr == nil, Msg: filesMsg(files, exErr)})

		// pppd ships as a relocatable tree (it dlopens radius.so + OpenSSL
		// providers, so it can't be one static binary). Extract it and, if the
		// host has no pppd of its own, point /usr/sbin/pppd + /usr/lib/pppd at the
		// bundle so both the daemon and its plugins resolve to it.
		if needsFeature(selected, featPppd) && backend.HasPppdBundle() {
			pErr := backend.ExtractPppdBundle()
			emit(ProvisionStep{Name: "extract pppd bundle", OK: pErr == nil, Msg: msgOrOK(pErr)})
			lErr := backend.LinkSystemPppd()
			emit(ProvisionStep{Name: "link system pppd", OK: lErr == nil, Msg: msgOrOK(lErr)})
			plErr := backend.LinkPluginDir()
			emit(ProvisionStep{Name: "link pppd plugin dir", OK: plErr == nil, Msg: msgOrOK(plErr)})
		}

		// SSTP accel-ppp bundle (G1). accel-pppd is a relocatable tree like pppd (it
		// dlopens the sstp/radius/auth modules + their deps), so extract it and point
		// /usr/lib/accel-ppp at the bundle's module dir so the bare [modules] names in
		// the generated accel-ppp.conf resolve to the bundled .so's. The daemon/CLI
		// binaries themselves resolve via daemonBin → backend.AccelBinPath, so no
		// PATH symlink is needed here.
		if needsFeature(selected, featAccel) && backend.HasAccelBundle() {
			aErr := backend.ExtractAccelBundle()
			emit(ProvisionStep{Name: "extract accel-ppp (SSTP) bundle", OK: aErr == nil, Msg: msgOrOK(aErr)})
			amErr := backend.LinkAccelModuleDir()
			emit(ProvisionStep{Name: "link accel-ppp module dir", OK: amErr == nil, Msg: msgOrOK(amErr)})
		}

		// IKEv2 strongSwan bundle. charon is a relocatable tree (it dlopens its plugins),
		// so extract it and symlink /usr/lib/ipsec at the bundle so charon's absolute-path
		// plugin dlopens resolve to the bundled .so's. Binaries resolve via
		// backend.StrongswanBinPath, so no PATH symlink is needed.
		if needsFeature(selected, featStrongswan) && backend.HasStrongswanBundle() {
			swErr := backend.ExtractStrongswanBundle()
			emit(ProvisionStep{Name: "extract strongswan (IKEv2) bundle", OK: swErr == nil, Msg: msgOrOK(swErr)})
			swlErr := backend.LinkStrongswanIpsecDir()
			emit(ProvisionStep{Name: "link strongswan ipsec dir", OK: swlErr == nil, Msg: msgOrOK(swlErr)})
		}

		// pptpd execs pptpctrl from a fixed compiled-in path; point it at the
		// extracted bundle so pptpd works from any install dir.
		if needsFeature(selected, featPptpCtrl) {
			clErr := backend.LinkPptpCtrl()
			emit(ProvisionStep{Name: "link pptpctrl", OK: clErr == nil, Msg: msgOrOK(clErr)})
		}

		// The bundled daemons run as child processes of the panel (not systemd),
		// so any leftover units from the old design are torn down here.
		migrateFromSystemd()
		emit(ProvisionStep{Name: "run daemons as child processes", OK: true, Msg: "ok"})
	}

	// The VPN data plane needs nftables (TPROXY steering + traffic accounting) and
	// iproute2 (the fwmark → table 100 policy route). They're present on almost
	// every host, but minimal cloud/container images can omit them — without them
	// clients connect but no traffic routes. Install when missing (no-op if present).
	emit(ensureCommand("nftables", "nft", nftablesPackage))
	emit(ensureCommand("iproute2 (ip)", "ip", iproutePackage))

	// IPsec for L2TP/IPsec: on the bundled path (amd64) the extracted strongSwan/charon
	// serves the IKEv1 transport layer alongside IKEv2 on one daemon, so no host package
	// is needed. Only fall back to host libreswan on arches without the strongSwan bundle.
	if needsFeature(selected, featStrongswan) && !backend.HasStrongswanBundle() {
		emit(ensureLibreswan())
	}

	// L2TP/PPTP need PPP kernel modules that minimal/cloud kernels omit. Best-
	// effort install of the distro's full kernel-modules package. When the modules
	// ship only in a newer kernel, this reports that a reboot is needed to load them.
	var mods []string
	var pkg string
	if needsFeature(selected, featKernelMods) {
		mods, pkg = s.provisionKernelModules(emit, requiredModules)
	}

	// AmneziaWG: DKMS-build + load the out-of-tree `amneziawg` module from the vendored
	// source (the project's only on-host compile). Warn-and-degrade on failure.
	//
	// This MUST run AFTER provisionKernelModules. That step can install a fuller kernel on
	// a cut-down cloud image (Debian's "cloud" flavour ships no PPP/L2TP) and ask for a
	// reboot, so the kernel this host will actually boot is not the one running now.
	// Building first meant the module was compiled for the kernel being left behind, and
	// AmneziaWG came back "module not found" after the reboot until setup was run a second
	// time. Running here, the incoming kernel and its headers are already on disk, so the
	// `dkms autoinstall` inside this step covers it too.
	if needsFeature(selected, featAmneziawg) {
		emit(ensureAmneziawg())
	}

	// Clear any distro deny-list/disable for our modules (and their dependencies) so
	// systemd-modules-load auto-loads them on boot (Fedora/RHEL blacklist the L2TP
	// modules; CIS-hardened hosts may `install <mod> /bin/false` others). This MUST
	// run after the kernel-modules install above: on Fedora/RHEL the blacklist files
	// ship WITH kernel-modules-extra, so they don't exist until that package is
	// installed — clearing earlier would find nothing and the module would stay
	// deny-listed after the reboot. Especially important on the reboot-required path,
	// where the modules only load on the next boot and must not be deny-listed then.
	if cleared, log := unblacklistVpnModules(); len(cleared) > 0 {
		emit(ProvisionStep{Name: "enable VPN modules", OK: true,
			Msg: "cleared distro deny-list/disable for " + strings.Join(cleared, ", ") + " (auto-loads on boot)", Log: log})

		// An `install <mod> /bin/false` rule blocks even the explicit modprobe run
		// earlier in this function, so a just-freed module isn't loaded yet. Load any
		// that are available now; `blacklist`-only modules already loaded above.
		var loaded []string
		for _, m := range requiredModules {
			if moduleLoaded(m) {
				continue
			}
			if exec.Command("modprobe", m).Run() == nil && moduleLoaded(m) {
				loaded = append(loaded, m)
			}
		}
		if len(loaded) > 0 {
			emit(ProvisionStep{Name: "load freed VPN modules", OK: true, Msg: "loaded " + strings.Join(loaded, ", ")})
		}
	}

	return mods, pkg
}

// provisionKernelModules makes the VPN PPP/L2TP kernel modules available when the
// running kernel lacks them. It is best-effort and non-interactive: it installs
// the right package for the distro, loads what it can into the running kernel,
// and — when the modules only ship in a fuller kernel it had to install — pins
// that kernel in the bootloader and reports that a reboot is needed (rather than
// rebooting). It returns the modules that only load after a reboot and the
// package that was installed.
//
// Per-distro behaviour (see KernelModulesPackage / InstallKernelModules):
//   - Ubuntu: linux-modules-extra-<running> adds modules to the RUNNING kernel →
//     no reboot. Cut-down flavours (kvm) fall back to linux-generic → reboot.
//   - Debian: cloud images omit PPP/L2TP, so the generic linux-image-<arch> is
//     installed → reboot, and the bootloader is pinned to it (a same-version
//     cloud kernel would otherwise stay the GRUB default).
//   - Fedora/RHEL/Alma/CentOS: kernel-modules-extra-<running> → no reboot.
//   - Arch: stock kernel already ships the modules → nothing to do.
//
// `want` is the module set the current selection needs, so a run that installed
// only WireGuard never installs a kernel package for PPP it will not use.
func (s *CoreService) provisionKernelModules(emit func(ProvisionStep), want []string) (rebootModules []string, rebootPkg string) {
	missing := missingModules(want)
	if len(missing) == 0 {
		return nil, ""
	}
	distro := distroPretty()

	pkg := KernelModulesPackage()
	if pkg == "" {
		emit(ProvisionStep{Name: "kernel modules", OK: false,
			Msg: "missing " + strings.Join(missing, ", ") + " on " + distro +
				" — no kernel-modules package known for this distro; load them manually"})
		return nil, ""
	}

	emit(ProvisionStep{Name: "kernel modules (" + distro + ")", OK: true,
		Msg: "missing " + strings.Join(missing, ", ") + " — installing " + pkg})

	installed, still, newKernel, log, err := s.InstallKernelModules(want)
	if err != nil {
		emit(ProvisionStep{Name: "install " + pkg, OK: false, Msg: err.Error(), Log: log})
		return nil, ""
	}
	if len(still) == 0 {
		emit(ProvisionStep{Name: "install " + installed, OK: true,
			Msg: "modules loaded into the running kernel — no reboot needed", Log: log})
		return nil, ""
	}

	// Whatever is still missing only exists in a freshly installed kernel that
	// isn't booted yet. Report it and make the bootloader boot that kernel.
	if newKernel == "" {
		emit(ProvisionStep{Name: "install " + installed, OK: true, Warn: true,
			Msg: "installed; " + strings.Join(still, ", ") + " load after a reboot into the new kernel", Log: log})
		return still, installed
	}

	emit(ProvisionStep{Name: "install " + installed, OK: true, Warn: true,
		Msg: "installed kernel " + newKernel + "; " + strings.Join(still, ", ") + " load after reboot", Log: log})

	bootMsg, bootErr := ensureBootloaderBootsKernel(newKernel)
	emit(ProvisionStep{Name: "set default boot kernel", OK: bootErr == nil, Msg: bootStepMsg(bootMsg, bootErr)})

	return still, installed
}

func bootStepMsg(msg string, err error) string {
	if err != nil {
		return err.Error()
	}
	return msg
}

// provisionRun holds the state of the single, in-progress or most-recent
// background provisioning run, so the Core Settings page can poll a live log.
// Provisioning is single-admin and one-at-a-time, so one global run suffices.
var provisionRun struct {
	mu             sync.Mutex
	running        bool
	done           bool
	steps          []ProvisionStep
	rebootRequired bool
	rebootModules  []string
	rebootPkg      string
}

// StartProvision launches provisioning for the given cores in the background and
// returns true, or returns false without starting a second run if one is already
// in progress. On completion it persists the provisioned flag so the setup gate
// clears, and records the cores the host is now set up for.
//
// A nil/empty selection means every installable core, which keeps the CLI and any
// caller that predates the picker working exactly as before.
func (s *CoreService) StartProvision(cores []string) bool {
	provisionRun.mu.Lock()
	if provisionRun.running {
		provisionRun.mu.Unlock()
		return false
	}
	provisionRun.running = true
	provisionRun.done = false
	provisionRun.steps = nil
	provisionRun.rebootRequired = false
	provisionRun.rebootModules = nil
	provisionRun.rebootPkg = ""
	provisionRun.mu.Unlock()

	selected := validCoreNames(cores)
	if len(selected) == 0 {
		selected = installableCores()
	}
	// Captured BEFORE the run: runProvisionSteps provisions for the union of this
	// and the selection, and the same union is what gets persisted below.
	already := s.installedCoreNames()

	go func() {
		var cs CoreService // CoreService is zero-value usable and stateless
		mods, pkg := cs.runProvisionSteps(func(st ProvisionStep) {
			provisionRun.mu.Lock()
			provisionRun.steps = append(provisionRun.steps, st)
			provisionRun.mu.Unlock()
		}, selected)
		var ss SettingService
		if err := ss.SetVpnProvisioned(true); err != nil {
			logger.Warning("failed to persist vpnProvisioned flag:", err)
		}
		// Record the cores this host is now set up for: what it already had plus
		// what this run added. Additive, so "add one core" never drops the rest,
		// and a core absent from the list is what makes the Core Settings page
		// offer it under "Add core".
		if err := ss.SetProvisionedProtocols(orderedCoreNames(append(already, selected...))); err != nil {
			logger.Warning("failed to persist provisionedProtocols:", err)
		}

		// With provisioning finished and no reboot pending, actively bring the VPN
		// stack up so a completed setup leaves everything running — the operator
		// shouldn't have to reboot or re-run setup to get services started. Init*
		// regenerate configs and (re)start the daemons for whatever inbounds already
		// exist (a no-op when there are none, e.g. provision-then-add-inbound), and
		// a forced xray restart binds the per-inbound dokodemo ports. When a reboot
		// IS required (kernel modules only load into the freshly booted kernel) this
		// is skipped: the post-reboot panel start runs the same Init* path.
		if len(mods) == 0 {
			cs.l2tpService.InitL2tp()
			cs.pptpService.InitPptp()
			cs.openvpnService.InitOpenVpn()
			cs.ocservService.InitOcserv()
			cs.sstpService.InitSstp()
			cs.ikev2Service.InitIkev2()
			if err := cs.xrayService.RestartXray(true); err != nil {
				logger.Warning("provision: failed to restart xray after setup:", err)
			}
		}

		provisionRun.mu.Lock()
		provisionRun.running = false
		provisionRun.done = true
		provisionRun.rebootRequired = len(mods) > 0
		provisionRun.rebootModules = mods
		provisionRun.rebootPkg = pkg
		provisionRun.mu.Unlock()
	}()
	return true
}

// ProvisionRunState is a snapshot of the background provisioning run, returned to
// the Core Settings page as it polls for live progress.
type ProvisionRunState struct {
	Running        bool            `json:"running"`
	Done           bool            `json:"done"`
	Steps          []ProvisionStep `json:"steps"`
	RebootRequired bool            `json:"rebootRequired"`
	RebootModules  []string        `json:"rebootModules"`
	RebootPkg      string          `json:"rebootPkg"`
}

// ProvisionState returns the current/most-recent provisioning run's progress: a
// copy of the steps emitted so far, whether it is running or done, and whether a
// reboot is needed to finish (kernel modules that only load on a fresh boot).
func (s *CoreService) ProvisionState() ProvisionRunState {
	provisionRun.mu.Lock()
	defer provisionRun.mu.Unlock()
	steps := make([]ProvisionStep, len(provisionRun.steps))
	copy(steps, provisionRun.steps)
	mods := make([]string, len(provisionRun.rebootModules))
	copy(mods, provisionRun.rebootModules)
	return ProvisionRunState{
		Running:        provisionRun.running,
		Done:           provisionRun.done,
		Steps:          steps,
		RebootRequired: provisionRun.rebootRequired,
		RebootModules:  mods,
		RebootPkg:      provisionRun.rebootPkg,
	}
}

// Reboot restarts the host machine after a short delay so the in-flight HTTP
// response is delivered first. It is used to load kernel modules that a
// provisioning package added but that only become active in a freshly booted
// kernel (L2TP/PPTP on minimal cloud images).
func (s *CoreService) Reboot() error {
	if !commandExists("systemctl") && !commandExists("reboot") && !commandExists("shutdown") {
		return fmt.Errorf("no reboot command available on this host")
	}
	go func() {
		time.Sleep(1500 * time.Millisecond)
		if commandExists("systemctl") {
			if err := exec.Command("systemctl", "reboot").Run(); err == nil {
				return
			}
		}
		if commandExists("reboot") {
			if err := exec.Command("reboot").Run(); err == nil {
				return
			}
		}
		_ = exec.Command("shutdown", "-r", "now").Run()
	}()
	return nil
}

func filesMsg(files []string, err error) string {
	if err != nil {
		return err.Error()
	}
	if len(files) == 0 {
		return "nothing to do"
	}
	return fmt.Sprintf("%d file(s)", len(files))
}

// firewallStepMsg summarizes what ensureVpnHostNetworking did, for the setup output.
func firewallStepMsg() string {
	if firewalldRunning() {
		return "firewalld active — trusted " + vpnAddrSpace
	}
	return "rp_filter set loose; no active firewalld"
}

func msgOrOK(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}
