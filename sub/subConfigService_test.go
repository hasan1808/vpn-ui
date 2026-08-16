package sub

import (
	"strconv"
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// The renderer's Remark already carries the device number and endpoint label, so the
// button text must not compose its own: that produced "WireGuard Device 1 Device 1 - edge".
func TestWgLabelUsesRendererRemarkAsIs(t *testing.T) {
	cases := []struct {
		name, proto, cfgRemark, inboundRemark, want string
	}{
		{"device and endpoint", "WireGuard", "Device 2 - edge", "home",
			"WireGuard Device 2 - edge (home)"},
		{"endpoint only", "AmneziaWG", "edge", "home", "AmneziaWG edge (home)"},
		{"single config", "WireGuard", "", "home", "WireGuard config (home)"},
		{"no inbound remark", "WireGuard", "", "", "WireGuard config"},
		{"remark is whitespace", "AmneziaWG", "  ", "  ", "AmneziaWG config"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wgLabel(c.proto, c.cfgRemark, c.inboundRemark); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

// greInbound builds a GRE inbound with a concrete Listen so the rendered server address
// comes from the inbound and not from whatever the test host's routing table answers
// (RenderPeerConfigs asks the kernel when Listen is a wildcard).
func greInbound(remark string, userLimit int, peers string) *model.Inbound {
	return &model.Inbound{
		Id:       7,
		Remark:   remark,
		Protocol: model.GRE,
		Listen:   "203.0.113.9",
		Settings: `{"userLimit":` + strconv.Itoa(userLimit) +
			`,"clients":[{"email":"alice","enable":true,"slot":0,"peers":[` + peers + `]}]}`,
	}
}

// A GRE peer ships as TWO files, one per platform. A customer runs one recipe and never
// both, and the Key is what the download route resolves, so it has to separate the
// platforms as well as the peers: without that, both files of a peer would serve whichever
// one ConfigFiles happened to list first.
func TestGreConfigFilesSplitByPlatform(t *testing.T) {
	s := &SubService{address: "vpn.example.com", remarkModel: "-ieo"}
	in := greInbound("home", 2,
		`{"peerIp":"198.51.100.4","remark":"office"},{"peerIp":"","remark":""}`)

	files := s.inboundConfigFiles(in, "alice", "vpn.example.com")
	if len(files) != 4 {
		t.Fatalf("want 2 peers x 2 platforms = 4 files, got %d: %+v", len(files), files)
	}

	seen := map[string]bool{}
	for _, f := range files {
		for _, v := range []string{"key " + f.Key, "filename " + f.Filename, "label " + f.Label} {
			if seen[v] {
				t.Fatalf("duplicate %s: one download shadows the other", v)
			}
			seen[v] = true
		}
		if f.Protocol != string(model.GRE) {
			t.Fatalf("protocol: got %q", f.Protocol)
		}
		if f.ContentType != "text/plain; charset=utf-8" {
			t.Fatalf("content type: got %q", f.ContentType)
		}
	}

	// Each half carries its own platform's commands and not the other's, and names the
	// peer: by the admin's remark when there is one, by slot number when there is not.
	for _, want := range []struct{ key, label, filename, has, hasNot string }{
		{"gre-7-0-mikrotik", "GRE MikroTik office (home)", "home-gre-peer1-mikrotik.txt",
			"/interface gre add", "ip link add"},
		{"gre-7-0-linux", "GRE Linux office (home)", "home-gre-peer1-linux.txt",
			"ip link add gre-vpnui", "/interface gre add"},
		{"gre-7-1-mikrotik", "GRE MikroTik Peer 2 (home)", "home-gre-peer2-mikrotik.txt",
			"/interface gre add", "ip link add"},
		{"gre-7-1-linux", "GRE Linux Peer 2 (home)", "home-gre-peer2-linux.txt",
			"ip link add gre-vpnui", "/interface gre add"},
	} {
		t.Run(want.key, func(t *testing.T) {
			var got *SubConfigFile
			for i := range files {
				if files[i].Key == want.key {
					got = &files[i]
				}
			}
			if got == nil {
				t.Fatalf("no file with key %q", want.key)
			}
			if got.Label != want.label {
				t.Fatalf("label:\n got=%q\nwant=%q", got.Label, want.label)
			}
			if got.Filename != want.filename {
				t.Fatalf("filename:\n got=%q\nwant=%q", got.Filename, want.filename)
			}
			if !strings.Contains(got.Content, want.has) {
				t.Fatalf("content is missing %q:\n%s", want.has, got.Content)
			}
			if strings.Contains(got.Content, want.hasNot) {
				t.Fatalf("content leaked the other platform's %q:\n%s", want.hasNot, got.Content)
			}
		})
	}
}

// One peer, no remarks: the platform still has to reach the label and the filename, and
// nothing invents a peer number the account does not have.
func TestGreConfigFilesSinglePeer(t *testing.T) {
	s := &SubService{address: "vpn.example.com", remarkModel: "-ieo"}
	files := s.inboundConfigFiles(greInbound("", 1, `{"peerIp":"198.51.100.4","remark":""}`),
		"alice", "vpn.example.com")
	if len(files) != 2 {
		t.Fatalf("want 1 peer x 2 platforms = 2 files, got %d: %+v", len(files), files)
	}
	for i, want := range []struct{ label, filename string }{
		{"GRE MikroTik", "gre-mikrotik.txt"},
		{"GRE Linux", "gre-linux.txt"},
	} {
		if files[i].Label != want.label {
			t.Fatalf("label %d:\n got=%q\nwant=%q", i, files[i].Label, want.label)
		}
		if files[i].Filename != want.filename {
			t.Fatalf("filename %d:\n got=%q\nwant=%q", i, files[i].Filename, want.filename)
		}
	}
}

// The filename lands in a Content-Disposition header and is built from admin-supplied
// text (inbound remarks, external-proxy labels), so it has to come out as a plain,
// single-token name whatever goes in.
func TestConfigFilenameIsSafe(t *testing.T) {
	cases := []struct {
		name, remark, proto, variant, ext, want string
	}{
		{"plain", "home", "wg", "Device 2 - edge", "conf", "home-Device-2-edge.conf"},
		{"empty remark falls back to protocol", "", "openvpn", "udp", "ovpn", "openvpn-udp.ovpn"},
		{"path separators dropped", "../../etc/passwd", "wg", "1", "conf", "etcpasswd-1.conf"},
		{"quotes and spaces dropped", `my "vpn" box`, "awg", "1", "conf", "my-vpn-box-1.conf"},
		{"non-ascii dropped", "خانه", "wg", "2", "conf", "wg-2.conf"},
		{"crlf dropped", "a\r\nb", "wg", "1", "conf", "ab-1.conf"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := configFilename(c.remark, c.proto, c.variant, c.ext)
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
			for _, bad := range []string{"/", "\\", `"`, " ", "\r", "\n", ".."} {
				if strings.Contains(got, bad) {
					t.Fatalf("filename %q still contains %q", got, bad)
				}
			}
		})
	}
}
