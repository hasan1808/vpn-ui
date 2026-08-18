package service

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"

	"github.com/pelletier/go-toml/v2"
)

// The advanced core config editor: operator-authored overrides for the config files
// the panel generates for each VPN core.
//
// WHY THE TEXT LIVES IN THE DATABASE AND NOT IN THE FILE. Hand-editing a core's config
// file is worthless here, because nothing on disk survives normal panel operation.
// Startup regenerates every core (Server.startTask -> Init<Core> -> GenerateAllConfigs
// + RestartServices), every inbound or client save of a protocol regenerates its core
// (the on<Core>Changed handlers in web/controller/inbound.go), and the 10s traffic job
// regenerates wgc/awg/gre/ikev2 and, through KillDisabledSessions, mtproto. mtproto's
// own generator says so in the file it writes: "Regenerated on every inbound/client
// change; edits are lost."
//
// So the operator's text is stored here and merged back in at the TAIL of every
// generator. That makes the stored text the SOURCE and the file on disk a pure render
// of "generated body + override", which is exactly the relationship xrayTemplateConfig
// already has with bin/config.json.

// Override modes.
const (
	// CoreConfigModeAppend puts the override after the generated body. It survives
	// inbound and client churn, because everything the generator knows how to write
	// is still written. It is what a POST with no mode at all gets, being the
	// conservative one of the two.
	//
	// NO UI OFFERS THIS ANY MORE, and that is deliberate rather than an oversight: the
	// editor shows one pane holding the WHOLE file, and a mode selector on top of that
	// is a second mental model for the operator to hold. The mode is still stored,
	// still merged and still accepted by the endpoint, so an override written through
	// the API keeps working. Do not delete it as dead code.
	CoreConfigModeAppend = "append"
	// CoreConfigModeReplace makes the override the whole file. Total control, at the
	// cost of freezing out every inbound and client added after it was written. This is
	// what the editor posts, always.
	CoreConfigModeReplace = "replace"
)

// coreConfigBanner marks where the panel's render stops and the operator's text
// starts. Every format the panel writes here takes `#` as a line comment.
const coreConfigBanner = "# ---- vpn-ui: operator override (Core Settings -> Edit config) ----"

// CoreConfigOverride is one stored edit.
type CoreConfigOverride struct {
	Mode string `json:"mode"`
	Text string `json:"text"`
}

// coreConfigCache memoizes the parsed override map.
//
// Not a micro-optimisation: applyCoreConfigOverride sits inside the generators, and
// the traffic job drives mtproto's generator every 10 seconds for every inbound, so an
// uncached read would put a settings SELECT on that path forever. Every write goes
// through setCoreConfigOverrides, which is the only invalidation point.
var coreConfigCache struct {
	sync.RWMutex
	loaded bool
	m      map[string]CoreConfigOverride
}

// coreConfigKey is the key one override is stored under: the core, the owning inbound
// (0 for a file the whole protocol shares), and a file discriminator.
//
// The file part is not redundant with the inbound: OpenVPN writes TWO configs for one
// inbound (server-udp.conf and server-tcp.conf), and l2tp and pptp each write a daemon
// config plus a pppd options file with no inbound of their own.
func coreConfigKey(core string, inboundId int, file string) string {
	return fmt.Sprintf("%s:%d:%s", core, inboundId, file)
}

// getCoreConfigOverrides returns every stored override.
//
// A corrupt blob degrades to "no overrides" rather than an error. The generators call
// this on every run, so failing here would leave the panel unable to write ANY config
// until the row was fixed by hand, and overrides are an opt-in extra.
func getCoreConfigOverrides() map[string]CoreConfigOverride {
	coreConfigCache.RLock()
	if coreConfigCache.loaded {
		m := coreConfigCache.m
		coreConfigCache.RUnlock()
		return m
	}
	coreConfigCache.RUnlock()

	var settingService SettingService
	raw, err := settingService.getString("coreConfigOverrides")

	coreConfigCache.Lock()
	defer coreConfigCache.Unlock()
	coreConfigCache.m = map[string]CoreConfigOverride{}
	coreConfigCache.loaded = true
	if err != nil {
		logger.Warning("core config: could not read coreConfigOverrides:", err)
		return coreConfigCache.m
	}
	if strings.TrimSpace(raw) == "" {
		return coreConfigCache.m
	}
	parsed := map[string]CoreConfigOverride{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		logger.Warning("core config: coreConfigOverrides is not valid JSON, ignoring it:", err)
		return coreConfigCache.m
	}
	coreConfigCache.m = parsed
	return coreConfigCache.m
}

// setCoreConfigOverrides stores the whole map and refreshes the cache.
func setCoreConfigOverrides(m map[string]CoreConfigOverride) error {
	if m == nil {
		m = map[string]CoreConfigOverride{}
	}
	blob, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var settingService SettingService
	if err := settingService.setString("coreConfigOverrides", string(blob)); err != nil {
		return err
	}
	coreConfigCache.Lock()
	coreConfigCache.m = m
	coreConfigCache.loaded = true
	coreConfigCache.Unlock()
	return nil
}

// copyCoreConfigOverrides returns a map a caller may mutate without racing the cache.
func copyCoreConfigOverrides() map[string]CoreConfigOverride {
	src := getCoreConfigOverrides()
	coreConfigCache.RLock()
	defer coreConfigCache.RUnlock()
	out := make(map[string]CoreConfigOverride, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// applyCoreConfigOverride merges the stored override into the body a generator just
// rendered. This is THE apply point: every hooked generator calls it as the last thing
// before writing, so the set of files an operator can override is the set of call sites
// of this function and nothing else.
//
// APPEND SEMANTICS ARE NOT UNIFORM ACROSS DAEMONS, so append mode cannot be promised to
// override an already-rendered directive, which is half the reason the editor stopped
// offering it. OpenVPN keeps the FIRST occurrence of a directive and ignores later ones,
// so an appended line there can only ADD an option the generated body never sets. pppd,
// xl2tpd, pptpd, ocserv and accel-ppp keep the last, so an appended line does win. TOML
// and swanctl are neither: an appended fragment joins whichever table or section the
// generated body ended in unless it opens its own. An API caller asking for append takes
// all of that on; the editor posts replace over the whole file, so what the operator sees
// is what lands.
func applyCoreConfigOverride(core string, inboundId int, file, rendered string) string {
	ov, ok := getCoreConfigOverrides()[coreConfigKey(core, inboundId, file)]
	if !ok {
		return rendered
	}
	return mergeCoreConfig(rendered, ov.Mode, ov.Text)
}

// mergeCoreConfig is the merge itself, with the values passed in rather than read from
// the database, so a save can check the exact bytes BEFORE storing them.
func mergeCoreConfig(rendered, mode, text string) string {
	if strings.TrimSpace(text) == "" {
		return rendered
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	if mode == CoreConfigModeReplace {
		return text
	}
	// Exactly one blank line between the render and the banner, always. An unstable
	// render would defeat mtproto's write-only-on-change guard and make telemt
	// hot-reload on every 10s tick.
	return strings.TrimRight(rendered, "\n") + "\n\n" + coreConfigBanner + "\n" + text
}

// --------------------------------------------------------------------------- //
//  The catalog of editable files
// --------------------------------------------------------------------------- //

// coreConfigTarget is one editable generated file.
type coreConfigTarget struct {
	Core      string
	InboundId int
	// File is the discriminator inside the storage key and the on-disk basename.
	File string
	// Label is the short name shown in the file picker.
	Label string
	// Remark is the owning inbound's name, so a per-inbound entry says which one.
	Remark string
	// Path is the absolute file the merged text is written to.
	Path string
	// Format picks the editor's syntax mode: "toml", or anything else for the
	// key/value-with-#-comments family (ini, pppd options, openvpn, swanctl).
	Format string

	// render produces the generated body with NO override applied. It is both what
	// "reset to default" goes back to and, with any override merged into it, the text
	// the editor is filled with.
	render func() (string, error)
	// validate is the pre-save check on the merged text, nil when the daemon offers
	// no way to check a config without running it.
	validate func(content string) error
}

// coreConfigTargets returns every editable file for a core, expanded over the
// protocol's inbounds.
//
// An empty slice is an honest answer, not a failure: wg-c, AmneziaWG, the GRE tunnel
// itself, SSH and RADIUS have no config file anywhere (the first three are programmed
// through kernel netlink, the last two run inside the panel binary), and a core with no
// inbound has nothing to generate a config for yet.
func (s *CoreService) coreConfigTargets(core string) []coreConfigTarget {
	switch core {
	case "l2tp":
		return s.l2tpConfigTargets()
	case "pptp":
		return s.pptpConfigTargets()
	case "openvpn":
		return s.openvpnConfigTargets()
	case "openconnect":
		return s.openconnectConfigTargets()
	case "sstp":
		return s.sstpConfigTargets()
	case "ikev2":
		return s.ikev2ConfigTargets()
	case "gre":
		return s.greConfigTargets()
	case "mtproto":
		return s.mtprotoConfigTargets()
	case "ipsec":
		return s.ipsecConfigTargets()
	}
	return nil
}

// CoreConfigTargets is the editor's read model: every editable file for a core with the
// text as it stands, plus any stored override.
//
// `current` is the ONE text the editor shows, so the modal needs no second pane to
// explain itself. It is computed, not read from the file: the file on disk is only ever a
// render of "generated body + override" and the next regeneration overwrites it, so
// reading it would be wrong exactly when it matters most, right after an inbound changed.
func (s *CoreService) CoreConfigTargets(core string) []map[string]any {
	overrides := getCoreConfigOverrides()
	targets := s.coreConfigTargets(core)
	out := make([]map[string]any, 0, len(targets))
	for _, t := range targets {
		generated := ""
		if t.render != nil {
			body, err := t.render()
			if err != nil {
				// A render failure is information, not a dead end: the operator still
				// has to be able to open the file and clear a bad override.
				generated = fmt.Sprintf("# this config could not be rendered: %v", err)
			} else {
				generated = body
			}
		}
		row := map[string]any{
			"core":    t.Core,
			"inbound": t.InboundId,
			"file":    t.File,
			"label":   t.Label,
			"remark":  t.Remark,
			"path":    t.Path,
			"format":  t.Format,
			"current": generated,
		}
		// `override` carries the mode as well as the text: the editor only needs to
		// know that one exists, but an override written through the API may be in
		// append mode, and then `current` is the merge rather than the text alone.
		if ov, ok := overrides[coreConfigKey(t.Core, t.InboundId, t.File)]; ok {
			row["override"] = ov
			row["current"] = mergeCoreConfig(generated, ov.Mode, ov.Text)
		}
		out = append(out, row)
	}
	return out
}

// CoreHasConfigTargets reports whether a core owns any editable file right now.
func (s *CoreService) CoreHasConfigTargets(core string) bool {
	return len(s.coreConfigTargets(core)) > 0
}

// --------------------------------------------------------------------------- //
//  Per-core target lists
// --------------------------------------------------------------------------- //

// coreConfigRemark names an inbound in a picker entry, so an inbound the operator never
// labelled still reads as something.
func coreConfigRemark(inbound *model.Inbound) string {
	if strings.TrimSpace(inbound.Remark) != "" {
		return inbound.Remark
	}
	return fmt.Sprintf("#%d", inbound.Id)
}

func (s *CoreService) l2tpConfigTargets() []coreConfigTarget {
	inbounds, err := s.l2tpService.GetL2tpInbounds()
	if err != nil || len(inbounds) == 0 {
		return nil
	}
	svc := &s.l2tpService
	out := []coreConfigTarget{
		{
			Core: "l2tp", File: "xl2tpd.conf", Label: "xl2tpd.conf",
			Path: "/etc/xl2tpd/xl2tpd.conf", Format: "ini",
			render: func() (string, error) { return svc.buildXl2tpdConfig(inbounds), nil },
		},
		{
			Core: "l2tp", File: "options.xl2tpd", Label: "options.xl2tpd (pppd)",
			Path: "/etc/ppp/options.xl2tpd", Format: "conf",
			render: func() (string, error) { return svc.buildPPPOptions(inbounds[0]) },
		},
	}
	// The swanctl connection exists only while some enabled inbound has IPsec on:
	// without a PSK the generator deletes the file rather than writing an empty one,
	// so offering an editor over it would be offering to edit nothing.
	//
	// It also splits into one file per inbound when each has its own listen address, so
	// the editor follows whichever shape writeL2tpSwanctlConn is actually writing —
	// otherwise the operator would be editing a path that no longer exists.
	if peers := l2tpPerListenPeers(svc.l2tpIpsecPeers(inbounds, true)); len(peers) > 0 {
		for _, peer := range peers {
			p := peer
			file := fmt.Sprintf("l2tp-%d.conf", p.inbound.Id)
			out = append(out, coreConfigTarget{
				Core: "l2tp", InboundId: p.inbound.Id, File: file,
				Label: file + " (IPsec, swanctl)", Remark: coreConfigRemark(p.inbound),
				Path: swanctlConfDir + "/" + file, Format: "swanctl",
				render:   func() (string, error) { return svc.buildL2tpSwanctlConnFor(p), nil },
				validate: validateSwanctlBraces,
			})
		}
		return out
	}
	if svc.buildL2tpSwanctlConn(inbounds) != "" {
		out = append(out, coreConfigTarget{
			Core: "l2tp", File: "l2tp.conf", Label: "l2tp.conf (IPsec, swanctl)",
			Path: swanctlConfDir + "/l2tp.conf", Format: "swanctl",
			render:   func() (string, error) { return svc.buildL2tpSwanctlConn(inbounds), nil },
			validate: validateSwanctlBraces,
		})
	}
	return out
}

func (s *CoreService) pptpConfigTargets() []coreConfigTarget {
	inbounds, err := s.pptpService.GetPptpInbounds()
	if err != nil || len(inbounds) == 0 {
		return nil
	}
	svc := &s.pptpService
	return []coreConfigTarget{
		{
			Core: "pptp", File: "pptpd.conf", Label: "pptpd.conf",
			Path: "/etc/pptpd.conf", Format: "ini",
			render: func() (string, error) { return svc.buildPptpdConfig(inbounds), nil },
		},
		{
			Core: "pptp", File: "pptpd-options", Label: "pptpd-options (pppd)",
			Path: "/etc/ppp/pptpd-options", Format: "conf",
			render: func() (string, error) { return svc.buildPPPOptions(inbounds[0]) },
		},
	}
}

func (s *CoreService) openvpnConfigTargets() []coreConfigTarget {
	inbounds, err := s.openvpnService.GetOpenVpnInbounds()
	if err != nil {
		return nil
	}
	svc := &s.openvpnService
	var out []coreConfigTarget
	for _, inbound := range inbounds {
		settings, err := svc.parseSettings(inbound)
		if err != nil {
			continue
		}
		ports := map[string]int{"udp": inbound.Port, "tcp": settings.tcpListenPort(inbound.Port)}
		enabled := map[string]bool{"udp": settings.udpEnabled(), "tcp": settings.tcpEnabled()}
		for _, proto := range []string{"udp", "tcp"} {
			if !enabled[proto] {
				continue
			}
			ib, st, pr, port := inbound, settings, proto, ports[proto]
			out = append(out, coreConfigTarget{
				Core: "openvpn", InboundId: inbound.Id, File: "server-" + proto + ".conf",
				Label: "server-" + proto + ".conf", Remark: coreConfigRemark(inbound),
				Path:   fmt.Sprintf("%s/server-%s.conf", svc.configDir(inbound.Id), proto),
				Format: "conf",
				render: func() (string, error) {
					return svc.buildServerConfig(ib, st, pr, port, svc.binaryPath()), nil
				},
			})
		}
	}
	return out
}

func (s *CoreService) openconnectConfigTargets() []coreConfigTarget {
	inbounds, err := s.ocservService.GetOcservInbounds()
	if err != nil {
		return nil
	}
	svc := &s.ocservService
	var out []coreConfigTarget
	for _, inbound := range inbounds {
		settings, err := svc.parseSettings(inbound)
		if err != nil {
			continue
		}
		ib, st := inbound, settings
		out = append(out, coreConfigTarget{
			Core: "openconnect", InboundId: inbound.Id, File: "ocserv.conf",
			Label: "ocserv.conf", Remark: coreConfigRemark(inbound),
			Path:   svc.configDir(inbound.Id) + "/ocserv.conf",
			Format: "conf",
			render: func() (string, error) { return svc.buildServerConfig(ib, st), nil },
			// The one daemon here that can check a config without serving it.
			validate: func(content string) error {
				return validateWithDaemon(svc.ocservBinaryPath(), "ocserv.conf", content,
					func(tmp string) []string { return []string{"-t", "-c", tmp} })
			},
		})
	}
	return out
}

func (s *CoreService) sstpConfigTargets() []coreConfigTarget {
	inbounds, err := s.sstpService.GetSstpInbounds()
	if err != nil {
		return nil
	}
	svc := &s.sstpService
	var out []coreConfigTarget
	for _, inbound := range inbounds {
		settings, err := svc.parseSettings(inbound)
		if err != nil {
			continue
		}
		ib, st := inbound, settings
		out = append(out, coreConfigTarget{
			Core: "sstp", InboundId: inbound.Id, File: "accel-ppp.conf",
			Label: "accel-ppp.conf", Remark: coreConfigRemark(inbound),
			Path:   svc.configDir(inbound.Id) + "/accel-ppp.conf",
			Format: "ini",
			render: func() (string, error) { return svc.buildServerConfig(ib, st), nil },
		})
	}
	return out
}

func (s *CoreService) ikev2ConfigTargets() []coreConfigTarget {
	inbounds, err := s.ikev2Service.GetIkev2Inbounds()
	if err != nil {
		return nil
	}
	svc := &s.ikev2Service
	var out []coreConfigTarget
	for _, inbound := range inbounds {
		settings, err := svc.parseSettings(inbound)
		if err != nil {
			continue
		}
		ib, st := inbound, settings
		base := svc.certBaseName(inbound.Id)
		out = append(out, coreConfigTarget{
			Core: "ikev2", InboundId: inbound.Id, File: base + ".conf",
			Label: base + ".conf (swanctl)", Remark: coreConfigRemark(inbound),
			Path:     swanctlConfDir + "/" + base + ".conf",
			Format:   "swanctl",
			render:   func() (string, error) { return svc.buildConnConf(ib, st), nil },
			validate: validateSwanctlBraces,
		})
	}
	return out
}

// greConfigTargets exposes GRE's swanctl connection and nothing else. GRE itself has no
// config file (the tunnel is kernel netlink state), and an inbound with IPsec off has no
// swanctl file either, so it contributes nothing here.
func (s *CoreService) greConfigTargets() []coreConfigTarget {
	inbounds, err := s.greService.GetGreInbounds()
	if err != nil {
		return nil
	}
	svc := &s.greService
	var out []coreConfigTarget
	for _, inbound := range inbounds {
		if !greInboundHasIpsec(inbound) {
			continue
		}
		settings, err := svc.parseSettings(inbound)
		if err != nil {
			continue
		}
		ib, st := inbound, settings
		// greIpsecConfName returns the full PATH, not a basename.
		name := fmt.Sprintf("gre-%d.conf", inbound.Id)
		out = append(out, coreConfigTarget{
			Core: "gre", InboundId: inbound.Id, File: name,
			Label: name + " (IPsec, swanctl)", Remark: coreConfigRemark(inbound),
			Path:     greIpsecConfName(inbound.Id),
			Format:   "swanctl",
			render:   func() (string, error) { return svc.buildGreSwanctlConn(ib, st), nil },
			validate: validateSwanctlBraces,
		})
	}
	return out
}

func (s *CoreService) mtprotoConfigTargets() []coreConfigTarget {
	inbounds, err := s.mtprotoService.GetMtprotoInbounds()
	if err != nil {
		return nil
	}
	svc := &s.mtprotoService
	var out []coreConfigTarget
	for _, inbound := range inbounds {
		settings, err := svc.parseSettings(inbound)
		if err != nil {
			continue
		}
		ib, st := inbound, settings
		out = append(out, coreConfigTarget{
			Core: "mtproto", InboundId: inbound.Id, File: "config.toml",
			Label: "config.toml", Remark: coreConfigRemark(inbound),
			Path:   svc.configDir(inbound.Id) + "/config.toml",
			Format: "toml",
			render: func() (string, error) { return svc.buildServerConfig(ib, st), nil },
			validate: func(content string) error {
				var probe map[string]any
				if err := toml.Unmarshal([]byte(content), &probe); err != nil {
					return common.NewError("not valid TOML:", err)
				}
				return nil
			},
		})
	}
	return out
}

// ipsecConfigTargets covers the SHARED strongSwan daemon config. The per-protocol
// swanctl connection files are listed under the protocol that owns them (l2tp, ikev2,
// gre), because that is the card the operator went looking at.
func (s *CoreService) ipsecConfigTargets() []coreConfigTarget {
	if !charonNeeded() {
		return nil
	}
	return []coreConfigTarget{
		{
			Core: "ipsec", File: "strongswan.conf", Label: "strongswan.conf (charon)",
			Path: "/etc/strongswan.conf", Format: "swanctl",
			render:   buildCharonConf,
			validate: validateSwanctlBraces,
		},
	}
}

// --------------------------------------------------------------------------- //
//  Validation
// --------------------------------------------------------------------------- //

// validateSwanctlBraces is the only offline check a swanctl-style config can get.
// strongSwan has no mode that parses a file outside /etc/swanctl, so the real verdict
// comes from the reload the apply performs. Catching an unbalanced brace here still
// spares the operator a restart round trip for the commonest typo.
func validateSwanctlBraces(content string) error {
	depth, line := 0, 0
	for _, raw := range strings.Split(content, "\n") {
		line++
		text := raw
		if i := strings.Index(text, "#"); i >= 0 {
			text = text[:i]
		}
		for _, r := range text {
			switch r {
			case '{':
				depth++
			case '}':
				depth--
				if depth < 0 {
					return common.NewErrorf("line %d: a closing brace with no matching opening brace", line)
				}
			}
		}
	}
	if depth > 0 {
		return common.NewErrorf("%d section(s) are never closed", depth)
	}
	return nil
}

// validateWithDaemon runs a daemon's own config check over the would-be file, written
// to a temp path so a rejected config never touches the live one.
//
// A missing binary is NOT an error. The core may simply not be installed on this host,
// and refusing the save over that would be a check that can only ever block.
func validateWithDaemon(bin, name, content string, args func(tmp string) []string) error {
	if bin == "" {
		return nil
	}
	if _, err := os.Stat(bin); err != nil {
		if _, err := exec.LookPath(bin); err != nil {
			logger.Debug("core config: skipping the config check, no binary at", bin)
			return nil
		}
	}
	dir, err := os.MkdirTemp("", "vpnui-cfgcheck-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	tmp := dir + "/" + name
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return err
	}
	out, err := exec.Command(bin, args(tmp)...).CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	return common.NewError(msg)
}

// --------------------------------------------------------------------------- //
//  Save
// --------------------------------------------------------------------------- //

// CoreConfigHealth is what a save reports back about the core it just restarted.
type CoreConfigHealth struct {
	OK bool `json:"ok"`
	// Reverted records that the override was rolled back because the core would not
	// stay up with it, so the UI does not tell the operator their text was kept.
	Reverted bool   `json:"reverted"`
	Logs     string `json:"logs"`
}

// SaveCoreConfigOverride validates, stores, applies and then verifies one override.
//
// The shape mirrors SaveXraySetting: render the would-be file, check it where a check
// exists, and store ONLY on success, so a rejected config leaves the running one alone.
// Where no daemon offers a config check (openvpn, accel-pppd, xl2tpd, pptpd) the check
// is done the only way left: apply it, watch the process manager, and put the old text
// back when the daemon will not stay up. Without that last step a bad save leaves the
// operator with a silently dead core and no feedback, which is exactly what procmgr's
// 5s restart loop produces on its own.
//
// The file is addressed by core + inbound + file name, all matched against a catalog the
// SERVER builds. No path ever arrives from the client: this endpoint writes files a root
// daemon then reads, so accepting a caller-supplied path would make it an arbitrary
// file-write primitive.
func (s *CoreService) SaveCoreConfigOverride(core string, inboundId int, file, mode, text string) (*CoreConfigHealth, error) {
	switch mode {
	case CoreConfigModeAppend, CoreConfigModeReplace:
	default:
		return nil, common.NewErrorf("unknown override mode %q", mode)
	}

	var target *coreConfigTarget
	for _, t := range s.coreConfigTargets(core) {
		if t.InboundId == inboundId && t.File == file {
			found := t
			target = &found
			break
		}
	}
	if target == nil {
		return nil, common.NewErrorf("%q is not a config file the %s core writes", file, core)
	}

	// The exact bytes that would land, so a check sees what the daemon will see.
	rendered := ""
	if target.render != nil {
		body, err := target.render()
		if err != nil {
			return nil, err
		}
		rendered = body
	}
	clearing := strings.TrimSpace(text) == ""
	if target.validate != nil && !clearing {
		if err := target.validate(mergeCoreConfig(rendered, mode, text)); err != nil {
			return nil, err
		}
	}

	overrides := copyCoreConfigOverrides()
	key := coreConfigKey(core, inboundId, file)
	previous, hadPrevious := overrides[key]
	if clearing {
		delete(overrides, key)
	} else {
		overrides[key] = CoreConfigOverride{Mode: mode, Text: text}
	}
	if err := setCoreConfigOverrides(overrides); err != nil {
		return nil, err
	}

	// Baseline BEFORE the apply. A core that was already down (every inbound disabled,
	// the daemon not installed) must not make every save look like it broke something.
	wasUp := s.coreProcessUp(core, inboundId)

	if err := s.ApplyCoreConfig(core); err != nil {
		logger.Warning("core config: applying the override for", core, "reported:", err)
	}
	if clearing || !wasUp || s.coreStaysUp(core, inboundId) {
		return &CoreConfigHealth{OK: true}, nil
	}

	// It went down. Put back exactly what was there and restart, then hand over the
	// daemon's own output: otherwise the operator gets a green save and a dead core.
	if hadPrevious {
		overrides[key] = previous
	} else {
		delete(overrides, key)
	}
	if err := setCoreConfigOverrides(overrides); err != nil {
		logger.Warning("core config: could not revert the override:", err)
	}
	if err := s.ApplyCoreConfig(core); err != nil {
		logger.Warning("core config: reverting the override for", core, "reported:", err)
	}
	return &CoreConfigHealth{Reverted: true, Logs: s.CoreLogs(core)}, nil
}

// ApplyCoreConfig regenerates a core's files from the database (which now carries the
// override) and restarts it, so the edit is live rather than pending.
//
// It deliberately does not re-run the routing or address-plan work the on<Core>Changed
// handlers do: a config edit cannot change the address plan, and re-running the
// allocator would reshuffle live sessions for nothing.
func (s *CoreService) ApplyCoreConfig(core string) error {
	var genErr error
	switch core {
	case "l2tp":
		genErr = s.l2tpService.GenerateAllConfigs()
	case "pptp":
		genErr = s.pptpService.GenerateAllConfigs()
	case "openvpn":
		// preserveLeases: an edit to the server config is not a change to the address
		// plan, so connected devices keep the tunnel IPs they were handed.
		genErr = s.openvpnService.GenerateAllConfigs(true)
	case "openconnect":
		genErr = s.ocservService.GenerateAllConfigs()
	case "sstp":
		genErr = s.sstpService.GenerateAllConfigs()
	case "ikev2":
		genErr = s.ikev2Service.GenerateAllConfigs()
	case "gre":
		genErr = s.greService.GenerateAllConfigs()
	case "mtproto":
		genErr = s.mtprotoService.GenerateAllConfigs()
	case "ipsec":
		// The shared charon. Restarting ikev2 runs syncCharon, which rewrites
		// strongswan.conf and reloads every connection on it, l2tp's and gre's too.
		genErr = writeCharonConf()
		core = "ikev2"
	default:
		return common.NewErrorf("the %s core has no editable configuration", core)
	}
	if err := s.RestartCore(core); err != nil {
		if genErr != nil {
			return common.NewErrorf("%v; %v", genErr, err)
		}
		return err
	}
	return genErr
}

// coreConfigProcNames are the process-manager keys a core's health is read from. The
// per-inbound cores are narrowed to the edited inbound, so an unrelated inbound's broken
// daemon can neither fail nor rescue this save.
func coreConfigProcNames(core string, inboundId int) []string {
	switch core {
	case "l2tp":
		return []string{"xl2tpd"}
	case "pptp":
		return []string{"pptpd"}
	case "openvpn":
		return []string{ovpnProcName(inboundId, "udp"), ovpnProcName(inboundId, "tcp")}
	case "openconnect":
		return []string{ocservProcName(inboundId)}
	case "sstp":
		return []string{sstpProcName(inboundId)}
	case "mtproto":
		return []string{mtprotoProcName(inboundId)}
	case "ikev2", "ipsec", "gre":
		// Every swanctl-backed file is loaded into the ONE shared charon.
		return []string{ikev2ProcName}
	}
	return nil
}

func (s *CoreService) coreProcessUp(core string, inboundId int) bool {
	for _, n := range coreConfigProcNames(core, inboundId) {
		if procMgr.IsRunning(n) {
			return true
		}
	}
	return false
}

// How long a core is watched after an apply, and how long it is given to settle first.
const (
	coreConfigWatchWindow = 10 * time.Second
	coreConfigWatchSettle = 2 * time.Second
	coreConfigWatchTick   = 500 * time.Millisecond
)

// coreStaysUp samples the daemon across coreConfigWatchWindow and reports whether it was
// up the whole time.
//
// Sampling rather than one check, because a config the daemon refuses does not fail the
// restart call: procmgr launches the daemon, the daemon exits, and procmgr relaunches it
// five seconds later, forever (procmgr.go supervise). A single check taken shortly after
// the restart can easily land inside the brief window where the doomed process is
// technically alive, and report a broken config as healthy. The first
// coreConfigWatchSettle is skipped so a daemon that binds slowly is not mistaken for a
// crash loop.
func (s *CoreService) coreStaysUp(core string, inboundId int) bool {
	names := coreConfigProcNames(core, inboundId)
	if len(names) == 0 {
		return true
	}
	start := time.Now()
	deadline := start.Add(coreConfigWatchWindow)
	for time.Now().Before(deadline) {
		time.Sleep(coreConfigWatchTick)
		if time.Since(start) < coreConfigWatchSettle {
			continue
		}
		up := false
		for _, n := range names {
			if procMgr.IsRunning(n) {
				up = true
				break
			}
		}
		if !up {
			return false
		}
	}
	return true
}

// ClearCoreConfigOverrides drops every override belonging to a core. Uninstalling a core
// has to call this: keeping the overrides would silently re-apply an edit written against
// this install's inbound ids to whatever inbound reuses an id after a reinstall.
func ClearCoreConfigOverrides(core string) {
	overrides := copyCoreConfigOverrides()
	prefix := core + ":"
	changed := false
	for key := range overrides {
		if strings.HasPrefix(key, prefix) {
			delete(overrides, key)
			changed = true
		}
	}
	if !changed {
		return
	}
	if err := setCoreConfigOverrides(overrides); err != nil {
		logger.Warning("core config: could not clear the overrides for", core, err)
	}
}
