package service

import (
	"net"
	"strings"
	"testing"

	"github.com/goccy/go-json"
)

// Whether a tunnel may ride a carrier that is an XRAY OUTBOUND is one question per
// protocol - "does this put anything but TCP and UDP on the wire" - and for GRE and PPTP
// it is the question that decides between a working tunnel and a tunnel that comes up and
// silently carries nothing. Both answers are pure: they read the stored settings and, for
// GRE, one kernel probe, which is passed in below so the shapes are pinned on any host.
// No kernel, no daemons, no database.

func carriableCfg(t *testing.T, tag, kind string, settings any) VpnOutboundConfig {
	t.Helper()
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal settings: %v", err)
	}
	return VpnOutboundConfig{Tag: tag, Kind: kind, Enable: true, Settings: raw}
}

// ---- gre --------------------------------------------------------------------------

// The three shapes of a GRE outbound and what each one puts on the wire. Only FOU without
// IPsec is UDP and nothing else; raw is IP protocol 47 and IPsec adds ESP, and a carrier
// tun swallows both without a word, so both have to be refused at save.
func TestGreOutCarriableShapes(t *testing.T) {
	cases := []struct {
		name      string
		st        greOutSettings
		fouUsable bool
		want      bool
		// wantSaid is what the operator must be able to act on; wantNotSaid is advice that
		// would send them into a refusal they cannot get out of.
		wantSaid    []string
		wantNotSaid []string
	}{
		{
			name:      "raw GRE is refused and told about both settings that fix it",
			st:        greOutSettings{Server: "198.51.100.7", Address: "10.9.1.5"},
			fouUsable: true,
			want:      false,
			wantSaid: []string{
				"IP protocol 47",
				"turn on UDP encapsulation (FOU)",
				"turn on IPsec",
				"VPN tunnel",
				"freedom outbound pinned to an interface",
			},
			wantNotSaid: []string{"GUE", "no FOU support"},
		},
		{
			name:      "raw GRE on a kernel with no fou module is told the truth instead",
			st:        greOutSettings{Server: "198.51.100.7", Address: "10.9.1.5"},
			fouUsable: false,
			want:      false,
			wantSaid: []string{
				"IP protocol 47",
				"no FOU support (module 'fou')",
				// The setting that IS available on a kernel with no fou module.
				"turn on IPsec",
				"VPN tunnel",
				"freedom outbound pinned to an interface",
			},
			// The one thing this host cannot do. Offering it here would be advice the
			// operator follows straight into Validate's own FOU refusal.
			wantNotSaid: []string{"turn on UDP encapsulation (FOU)"},
		},
		{
			name:      "FOU alone is UDP to the same server, so it rides",
			st:        greOutSettings{Server: "198.51.100.7", Address: "10.9.1.5", FouEnable: true, FouPort: 15547},
			fouUsable: true,
			want:      true,
		},
		{
			name:      "FOU with no explicit port still rides",
			st:        greOutSettings{Server: "198.51.100.7", Address: "10.9.1.5", FouEnable: true},
			fouUsable: true,
			want:      true,
		},
		{
			// Two different questions, kept apart on purpose. This one is "what is on the
			// wire", and the answer is UDP however this kernel feels about it; whether the
			// tunnel can be BUILT here is Validate's, and it refuses that save with the
			// module named. Answering "not carriable" here would blame the carrier for a
			// missing module and hide the real fault.
			name:      "FOU is a UDP shape even where the module is missing",
			st:        greOutSettings{Server: "198.51.100.7", Address: "10.9.1.5", FouEnable: true},
			fouUsable: false,
			want:      true,
		},
		{
			// ESP is IP protocol 50, which no carrier tun dispatches, so this rides only
			// because greOutBuildIpsecConf forces UDP encapsulation for a carried tunnel
			// and greOutRequireEncap refuses the bring-up when charon did not deliver it.
			// The two are one answer: flipping this to true without that readback is how
			// the IKEv1 silent failure would ship.
			name:      "IPsec alone rides, because a carried tunnel's ESP is forced into UDP 4500",
			st:        greOutSettings{Server: "198.51.100.7", Address: "10.9.1.5", IpsecEnable: true, IpsecPsk: "s3cret"},
			fouUsable: true,
			want:      true,
		},
		{
			// Not a carrier limitation: these two settings cancel each other, carried or
			// not, and the refusal is what stops the panel carrying an unencrypted tunnel
			// while the form says IPsec is on.
			name: "FOU and IPsec together are refused, because they cancel",
			st: greOutSettings{Server: "198.51.100.7", Address: "10.9.1.5",
				FouEnable: true, FouPort: 15547, IpsecEnable: true, IpsecPsk: "s3cret"},
			fouUsable: true,
			want:      false,
			wantSaid: []string{
				"local_ts = dynamic[gre]",
				"IP protocol 47",
				"turn one of them off",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := tc.st
			got, why := greOutCarriable(&st, tc.fouUsable)
			if got != tc.want {
				t.Fatalf("carriable = %v, want %v (said %q)", got, tc.want, why)
			}
			if got {
				if why != "" {
					t.Errorf("a carriable tunnel came with a refusal to show: %q", why)
				}
				return
			}
			if why == "" {
				t.Fatal("refused with nothing for the operator to read")
			}
			for _, want := range tc.wantSaid {
				if !strings.Contains(why, want) {
					t.Errorf("the refusal does not mention %q, so it cannot be acted on: %s", want, why)
				}
			}
			for _, unwanted := range tc.wantNotSaid {
				if strings.Contains(why, unwanted) {
					t.Errorf("the refusal mentions %q, which is not usable here: %s", unwanted, why)
				}
			}
			// The framework wraps this into "<tag> cannot be carried by the "<x>" outbound:
			// <why>. ..." so a leading capital or a trailing full stop lands mid-sentence.
			if strings.HasSuffix(why, ".") {
				t.Errorf("the refusal ends in a full stop and is composed into a longer sentence: %s", why)
			}
		})
	}
}

// The driver's own method, which is what the framework calls. Only the two shapes whose
// answer cannot depend on the kernel probe are asked here, so this passes on a host with
// or without the fou module.
func TestGreOutCarriableOverProxy(t *testing.T) {
	t.Run("FOU rides", func(t *testing.T) {
		cfg := carriableCfg(t, "gre-a", VpnOutGre, greOutSettings{
			Server: "198.51.100.7", Address: "10.9.1.5", FouEnable: true, FouPort: 15547,
		})
		if ok, why := (greOutDriver{}).CarriableOverProxy(cfg); !ok {
			t.Fatalf("a FOU tunnel was refused, and UDP is all it puts on the wire: %s", why)
		}
	})

	t.Run("IPsec rides", func(t *testing.T) {
		cfg := carriableCfg(t, "gre-b", VpnOutGre, greOutSettings{
			Server: "198.51.100.7", Address: "10.9.1.5", IpsecEnable: true, IpsecPsk: "s3cret",
		})
		if ok, why := (greOutDriver{}).CarriableOverProxy(cfg); !ok {
			t.Fatalf("an IPsec tunnel was refused, and a carried one's ESP is forced into UDP 4500: %s", why)
		}
	})

	t.Run("FOU and IPsec together are refused", func(t *testing.T) {
		cfg := carriableCfg(t, "gre-e", VpnOutGre, greOutSettings{
			Server: "198.51.100.7", Address: "10.9.1.5",
			FouEnable: true, IpsecEnable: true, IpsecPsk: "s3cret",
		})
		ok, why := (greOutDriver{}).CarriableOverProxy(cfg)
		if ok {
			t.Fatal("a tunnel whose IPsec policy can never match was carried and called encrypted")
		}
		if !strings.Contains(why, "cancel") {
			t.Errorf("the refusal does not say the two settings cancel: %s", why)
		}
	})

	// Unknown shape has to refuse. Saying yes here would accept a tunnel nobody has read
	// the settings of, and the cost of being wrong is silent packet loss.
	t.Run("unreadable settings refuse rather than guess", func(t *testing.T) {
		cfg := VpnOutboundConfig{Tag: "gre-c", Kind: VpnOutGre, Enable: true, Settings: []byte(`{"fouEnable":`)}
		if ok, why := (greOutDriver{}).CarriableOverProxy(cfg); ok {
			t.Fatalf("a tunnel with unreadable settings was declared carriable (%q)", why)
		}
	})

	// A tunnel with nothing configured yet is raw GRE by default, and the answer must not
	// depend on how empty the blob is.
	t.Run("an empty blob is the raw shape", func(t *testing.T) {
		for _, raw := range [][]byte{nil, []byte(`{}`)} {
			cfg := VpnOutboundConfig{Tag: "gre-d", Kind: VpnOutGre, Enable: true, Settings: raw}
			if ok, _ := (greOutDriver{}).CarriableOverProxy(cfg); ok {
				t.Fatalf("settings %q were taken as carriable; raw GRE is IP protocol 47", string(raw))
			}
		}
	})
}

// The line that makes a GRE-over-IPsec tunnel carriable at all, and the reason it must not
// appear anywhere else. Rendered, never written: a real connection file dropped into
// /etc/swanctl by a test would be picked up by any charon running on the same box.
func TestGreOutIpsecConfEncapsOnlyWhenCarried(t *testing.T) {
	st := &greOutSettings{
		Server: "198.51.100.7", Address: "10.9.1.5", IpsecEnable: true, IpsecPsk: `s3"cret`,
	}
	local, remote := net.ParseIP("203.0.113.4"), net.ParseIP("198.51.100.7")

	carried := greOutBuildIpsecConf("gre-a", st, local, remote, true)
	if !strings.Contains(carried, "\n        encap = yes\n") {
		t.Errorf("a carried tunnel's connection does not force UDP encapsulation, so its ESP is "+
			"raw IP protocol 50 and the carrier drops every packet:\n%s", carried)
	}

	plain := greOutBuildIpsecConf("gre-a", st, local, remote, false)
	if strings.Contains(plain, "encap") {
		t.Errorf("an UNCARRIED tunnel was given UDP encapsulation, which changes what leaves the "+
			"box for an operator who asked for nothing:\n%s", plain)
	}

	// The flag decides one line and nothing else. A drift here would mean two IPsec configs
	// to reason about instead of one with a switch.
	if len(strings.Split(carried, "\n")) != len(strings.Split(plain, "\n"))+1 {
		t.Errorf("carrying changed more than the single encap line:\ncarried:\n%s\nplain:\n%s", carried, plain)
	}
	// Still the transport-mode, protocol-47 child the far side expects, and the PSK is still
	// escaped: the split into a renderer must not have quietly dropped either.
	for _, want := range []string{"mode = transport", "local_ts = dynamic[gre]", `secret = "s3\"cret"`} {
		if !strings.Contains(carried, want) {
			t.Errorf("the rendered connection lost %q:\n%s", want, carried)
		}
	}
}

// ---- pptp -------------------------------------------------------------------------

// PPTP is refused whatever is in the form: the GRE data channel is not a setting. The point
// of the test is that no shape sneaks past, and that the message sends the operator to the
// carrier that does work rather than to a knob that does not exist.
func TestPptpOutCarriableOverProxy(t *testing.T) {
	shapes := []struct {
		name string
		st   pptpOutSettings
	}{
		{"a plain tunnel", pptpOutSettings{Server: "198.51.100.9", Username: "u", Password: "p"}},
		{"encryption off", pptpOutSettings{Server: "198.51.100.9", Username: "u", Password: "p", Mppe: "off"}},
		{"pap, no encryption", pptpOutSettings{Server: "198.51.100.9", Username: "u", Password: "p", AuthProto: "pap", Mppe: "off"}},
		{"nothing filled in yet", pptpOutSettings{}},
	}

	for _, tc := range shapes {
		t.Run(tc.name, func(t *testing.T) {
			cfg := carriableCfg(t, "pptp-a", VpnOutPPTP, tc.st)
			ok, why := (&pptpOutDriver{}).CarriableOverProxy(cfg)
			if ok {
				t.Fatal("PPTP was accepted onto a carrier that cannot move IP protocol 47")
			}
			for _, want := range []string{
				"1723",                    // the half that would ride
				"GRE, IP protocol 47",     // the half that would not
				"No setting changes that", // there is no knob, so do not send them hunting
				"VPN tunnel",              // what does work
				"freedom outbound pinned to an interface",
			} {
				if !strings.Contains(why, want) {
					t.Errorf("the refusal does not mention %q: %s", want, why)
				}
			}
			if strings.HasSuffix(why, ".") {
				t.Errorf("the refusal ends in a full stop and is composed into a longer sentence: %s", why)
			}
		})
	}

	// Same answer for a config that never parsed. Nothing in the blob can change it, and a
	// driver that leaned on the settings here would answer "carriable" for a broken one.
	t.Run("unreadable settings are refused too", func(t *testing.T) {
		cfg := VpnOutboundConfig{Tag: "pptp-b", Kind: VpnOutPPTP, Enable: true, Settings: []byte(`{"server":`)}
		if ok, _ := (&pptpOutDriver{}).CarriableOverProxy(cfg); ok {
			t.Fatal("PPTP with unreadable settings was declared carriable")
		}
	})
}

// ---- registration -------------------------------------------------------------------

// The gate is only ever reached through a type assertion on the REGISTERED driver, so a
// receiver mismatch (a value method on a pointer-registered driver, or the reverse) does
// not fail to compile: it makes the assertion fail and the tunnel is accepted onto a
// carrier that swallows it, with nothing said anywhere.
func TestVpnOutCarriableIsReachableFromTheRegistry(t *testing.T) {
	for _, kind := range []string{VpnOutGre, VpnOutPPTP} {
		d, err := vpnOutDriverFor(kind)
		if err != nil {
			t.Fatalf("no driver registered for %q: %v", kind, err)
		}
		if _, ok := d.(VpnOutCarriable); !ok {
			t.Errorf("the registered %q driver does not satisfy VpnOutCarriable, so the carrier gate is never asked", kind)
		}
	}
}
