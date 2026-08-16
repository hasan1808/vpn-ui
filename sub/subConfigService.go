package sub

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hasan1808/pro-ui/database/model"
)

// Config-file downloads for the subscriber page.
//
// Four protocols cannot be configured from a link alone: OpenVPN needs its .ovpn
// profile (CA + tls-crypt + cipher list), WireGuard (C) / AmneziaWG need a .conf per
// device (keys, address, DNS, and awg's obfuscation values), and GRE has no client app at
// all, so its artifact is the plain-text recipe to type into a router, one file per peer per
// platform (it is the only protocol here with no share link at all). The subscriber page
// therefore offers them as downloads, rendered by the same service functions the panel's
// own download buttons use, so a profile taken from the subscription is byte-for-byte the
// profile the admin sees: inbound settings and external proxies included.
//
// The subId is the only credential, exactly as for the subscription itself: the account
// is looked up FROM it, never from anything the caller passes, so a key naming another
// inbound resolves to nothing.

// SubConfigFile is one downloadable client config.
type SubConfigFile struct {
	Key         string // route key, "<proto>-<inboundId>-<variant>"
	Protocol    string
	Label       string // button text
	Filename    string
	ContentType string
	Content     string
}

// SubConfigLink is the page-facing half: what to show and where to fetch it.
type SubConfigLink struct {
	Label    string
	Filename string
	Url      string
}

// ConfigFiles renders every downloadable config the subscription's accounts have, in
// inbound order. host is the address the subscriber reached the sub server on, which is
// what the renderers fall back to when no external proxy is configured (the same rule
// the panel's own buttons follow, where it is the admin's browser host).
func (s *SubService) ConfigFiles(subId string, host string) []SubConfigFile {
	s.address = host
	inbounds, err := s.getInboundsBySubId(subId)
	if err != nil {
		return nil
	}

	var out []SubConfigFile
	seen := map[string]bool{}
	for _, inbound := range inbounds {
		switch inbound.Protocol {
		case model.OPENVPN, model.WGC, model.AWG, model.GRE:
		default:
			continue
		}
		clients, err := s.inboundService.GetClients(inbound)
		if err != nil {
			continue
		}
		for _, client := range clients {
			if !client.Enable || client.SubID != subId {
				continue
			}
			for _, cfg := range s.inboundConfigFiles(inbound, client.Email, host) {
				// An OpenVPN profile is per inbound, not per account (it carries no
				// credentials, the client is prompted), so two accounts of one inbound
				// sharing a subId would otherwise offer the same file twice.
				if seen[cfg.Key] {
					continue
				}
				seen[cfg.Key] = true
				out = append(out, cfg)
			}
		}
	}
	return out
}

// ConfigFile returns the one config the key names, or ok=false. It re-renders rather than
// caching, so a download always reflects the inbound as it stands now.
func (s *SubService) ConfigFile(subId string, host string, key string) (SubConfigFile, bool) {
	for _, cfg := range s.ConfigFiles(subId, host) {
		if cfg.Key == key {
			return cfg, true
		}
	}
	return SubConfigFile{}, false
}

// ConfigLinks is ConfigFiles reduced to what the page needs, with absolute URLs built the
// same way the subscription URLs are (so a configured subURI or a proxy host wins).
func (s *SubService) ConfigLinks(subId, host, scheme, hostWithPort, subPath string) []SubConfigLink {
	files := s.ConfigFiles(subId, host)
	if len(files) == 0 {
		return nil
	}
	base, _, _ := s.BuildURLs(scheme, hostWithPort, subPath, subPath, subPath, subId)
	if base == "" {
		return nil
	}
	links := make([]SubConfigLink, 0, len(files))
	for _, f := range files {
		links = append(links, SubConfigLink{
			Label:    f.Label,
			Filename: f.Filename,
			Url:      strings.TrimRight(base, "/") + "/configs/" + f.Key,
		})
	}
	return links
}

func (s *SubService) inboundConfigFiles(inbound *model.Inbound, email, host string) []SubConfigFile {
	switch inbound.Protocol {
	case model.OPENVPN:
		var out []SubConfigFile
		for _, proto := range []string{"udp", "tcp"} {
			// GenerateClientConfig refuses a transport the admin switched off (and an
			// inbound with no certificates), which is exactly the filter wanted here:
			// only offer profiles that would actually connect.
			content, err := s.openvpnService.GenerateClientConfig(inbound, proto, host)
			if err != nil {
				continue
			}
			out = append(out, SubConfigFile{
				Key:         fmt.Sprintf("ovpn-%d-%s", inbound.Id, proto),
				Protocol:    string(model.OPENVPN),
				Label:       "OpenVPN " + strings.ToUpper(proto) + labelSuffix(inbound.Remark),
				Filename:    configFilename(inbound.Remark, "openvpn", proto, "ovpn"),
				ContentType: "application/x-openvpn-profile",
				Content:     content,
			})
		}
		return out

	case model.WGC:
		cfgs, err := s.wgcService.RenderClientConfigs(inbound, email, host)
		if err != nil {
			return nil
		}
		out := make([]SubConfigFile, 0, len(cfgs))
		for i, cfg := range cfgs {
			out = append(out, SubConfigFile{
				Key:         fmt.Sprintf("wgc-%d-%d", inbound.Id, i),
				Protocol:    string(model.WGC),
				Label:       wgLabel("WireGuard", cfg.Remark, inbound.Remark),
				Filename:    configFilename(inbound.Remark, "wg", wgVariant(cfg.Remark, i), "conf"),
				ContentType: "application/x-wireguard-profile",
				Content:     cfg.Config,
			})
		}
		return out

	case model.AWG:
		cfgs, err := s.awgService.RenderClientConfigs(inbound, email, host)
		if err != nil {
			return nil
		}
		out := make([]SubConfigFile, 0, len(cfgs))
		for i, cfg := range cfgs {
			out = append(out, SubConfigFile{
				Key:         fmt.Sprintf("awg-%d-%d", inbound.Id, i),
				Protocol:    string(model.AWG),
				Label:       wgLabel("AmneziaWG", cfg.Remark, inbound.Remark),
				Filename:    configFilename(inbound.Remark, "awg", wgVariant(cfg.Remark, i), "conf"),
				ContentType: "application/x-wireguard-profile",
				Content:     cfg.Config,
			})
		}
		return out

	case model.GRE:
		// GRE has no client app and therefore no profile format: the artifact is the set of
		// values the customer types into their router, so it ships as plain text. The two
		// platforms are separate files rather than one blob, exactly as the panel splits
		// them: a customer runs one recipe, never both, and a combined file invites pasting
		// RouterOS syntax into a Linux shell.
		cfgs, err := s.greService.RenderPeerConfigs(inbound, email, host)
		if err != nil {
			return nil
		}
		multi := len(cfgs) > 1
		out := make([]SubConfigFile, 0, len(cfgs)*2)
		for i, cfg := range cfgs {
			for _, p := range []struct{ slug, name, content string }{
				{"mikrotik", "MikroTik", cfg.ConfigMikrotik},
				{"linux", "Linux", cfg.ConfigLinux},
			} {
				if strings.TrimSpace(p.content) == "" {
					continue
				}
				out = append(out, SubConfigFile{
					// The platform is part of the key, not just the filename: the key is
					// what the download route resolves, so without it both files of a peer
					// would serve whichever one ConfigFiles listed first.
					Key:         fmt.Sprintf("gre-%d-%d-%s", inbound.Id, i, p.slug),
					Protocol:    string(model.GRE),
					Label:       greLabel(p.name, cfg.Remark, inbound.Remark, cfg.PeerIndex, multi),
					Filename:    configFilename(inbound.Remark, "gre", greVariant(inbound.Remark, p.slug, cfg.PeerIndex, multi), "txt"),
					ContentType: "text/plain; charset=utf-8",
					Content:     p.content,
				})
			}
		}
		return out
	}
	return nil
}

// wgLabel names a WireGuard config. The renderer's own Remark already reads "Device 2 -
// edge" (device number only when the account has more than one, endpoint label only when
// external proxies are configured), so it is used as-is: composing a second device number
// on top produced "Device 1 Device 1 - edge".
func wgLabel(protoName, cfgRemark, inboundRemark string) string {
	label := protoName
	if r := strings.TrimSpace(cfgRemark); r != "" {
		label += " " + r
	} else {
		label += " config"
	}
	return label + labelSuffix(inboundRemark)
}

// wgVariant is the filename half of the same thing, falling back to the position so two
// configs of one inbound never collide on disk.
func wgVariant(cfgRemark string, index int) string {
	if r := strings.TrimSpace(cfgRemark); r != "" {
		return r
	}
	return strconv.Itoa(index + 1)
}

// greLabel names one GRE download. It cannot reuse wgLabel: a GRE peer remark is optional
// (a WireGuard config always gets "Device N" from its renderer), so an account with two
// unnamed peers would show the same button text twice. The slot number stands in when the
// admin left the peer unnamed, and only then, since "Peer 1" on a single-peer account is
// noise.
func greLabel(platform, peerRemark, inboundRemark string, peerIndex int, multi bool) string {
	label := "GRE " + platform
	if r := strings.TrimSpace(peerRemark); r != "" {
		label += " " + r
	} else if multi {
		label += " Peer " + strconv.Itoa(peerIndex+1)
	}
	return label + labelSuffix(inboundRemark)
}

// greVariant is the filename half of the same thing. A GRE artifact is a bare .txt rather
// than a .ovpn/.conf that names itself, so the protocol goes in the filename or the
// customer is left with "home-linux.txt" and nothing saying what it belongs to. It is
// dropped when the remark slugs away to nothing, because configFilename already falls back
// to "gre" there.
func greVariant(inboundRemark, platform string, peerIndex int, multi bool) string {
	parts := make([]string, 0, 3)
	if slugForFilename(inboundRemark) != "" {
		parts = append(parts, "gre")
	}
	if multi {
		parts = append(parts, "peer"+strconv.Itoa(peerIndex+1))
	}
	return strings.Join(append(parts, platform), "-")
}

func labelSuffix(remark string) string {
	if r := strings.TrimSpace(remark); r != "" {
		return " (" + r + ")"
	}
	return ""
}

// configFilename builds the download filename. Everything that reaches it is
// admin-supplied (an inbound remark, an external-proxy label), and it ends up in a
// Content-Disposition header, so it is reduced to a safe charset rather than quoted.
func configFilename(remark, proto, variant, ext string) string {
	name := slugForFilename(remark)
	if name == "" {
		name = proto
	}
	if v := slugForFilename(variant); v != "" {
		name += "-" + v
	}
	return name + "." + ext
}

func slugForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == ' ' || r == '.' || r == '-':
			// Runs collapse: "Device 1 - edge" would otherwise slug to "Device-1---edge".
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteRune('-')
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
