package service

import (
	"net"
	"strings"
	"testing"
)

// Forcing UDP encapsulation on the two IPsec client outbounds, and only when they are
// carried by an Xray outbound.
//
// Both drivers put ESP (IP protocol 50) on the wire, and a carrier tun dispatches TCP and
// UDP only, so a carried tunnel without `encap = yes` establishes its SA, reports itself
// up, and moves nothing. The knob is the fix; these tests pin the two halves of it that
// can be checked without a kernel or a daemon:
//
//   - the line appears in the generated swanctl connection when carried, and NOWHERE when
//     not, because forcing it on an uncarried tunnel costs 8 bytes a packet and hides a
//     real NAT for no gain;
//   - the settings fingerprint moves when carried-ness moves, which is what makes Up
//     re-dial. CarriedOverProxy is json:"-", so a fingerprint over the marshalled settings
//     alone cannot see it, and the tunnel would keep its raw-ESP SA under a carrier that
//     drops every packet of it.
//
// The third half, that charon and the peer actually agreed to it, is a readback of
// `swanctl --list-sas` and is pinned here against listings in the shape swanctl prints.

const ipsecEncapLine = "encap = yes"

// ikev2EncapSettings is a minimal but complete IKEv2 client: the builder takes the parsed
// shape, so every field it reads is set here rather than defaulted by parse().
func ikev2EncapSettings() *ikev2OutSettings {
	return &ikev2OutSettings{
		Server:   "203.0.113.9",
		AuthMode: "eap-mschapv2",
		Username: "account",
		Password: "hunter2",
	}
}

// stripFingerprint removes the generated fingerprint comment, which is expected to differ
// between a carried and an uncarried render and would otherwise mask the one difference
// these tests are about.
func ipsecEncapStripFingerprint(conf, mark string) string {
	var kept []string
	for _, ln := range strings.Split(conf, "\n") {
		if strings.HasPrefix(ln, mark) {
			continue
		}
		kept = append(kept, ln)
	}
	return strings.Join(kept, "\n")
}

func ipsecEncapCountLine(conf, needle string) int {
	n := 0
	for _, ln := range strings.Split(conf, "\n") {
		if strings.TrimSpace(ln) == needle {
			n++
		}
	}
	return n
}

func TestIkev2OutEncapOnlyWhenCarried(t *testing.T) {
	for _, mode := range []string{"eap-mschapv2", "psk", "cert"} {
		t.Run(mode, func(t *testing.T) {
			s := ikev2EncapSettings()
			s.AuthMode = mode
			s.Psk = "shared"

			plain := ikev2OutBuildConnConf("tun", "ike-tun", 4242, s, false)
			carried := ikev2OutBuildConnConf("tun", "ike-tun", 4242, s, true)

			if n := ipsecEncapCountLine(plain, ipsecEncapLine); n != 0 {
				t.Errorf("an uncarried tunnel forces UDP encapsulation (%d times):\n%s", n, plain)
			}
			if n := ipsecEncapCountLine(carried, ipsecEncapLine); n != 1 {
				t.Fatalf("a carried tunnel wrote %d encap lines, want exactly 1:\n%s", n, carried)
			}
			// Inside the connection block, at the same depth as mobike and fragmentation.
			// A child-level `encap` is not a key swanctl knows, and charon answers an
			// unknown key by refusing to load the connection at all.
			if !strings.Contains(carried, "\n        encap = yes\n") {
				t.Errorf("the encap line is not at connection level:\n%s", carried)
			}
			// The ONLY difference. Anything else moving with carried-ness would be a
			// second, unreviewed change to what the daemon is told.
			gotPlain := ipsecEncapStripFingerprint(plain, ikev2OutFingerprintMark)
			gotCarried := strings.Replace(ipsecEncapStripFingerprint(carried, ikev2OutFingerprintMark),
				"        encap = yes\n", "", 1)
			if gotPlain != gotCarried {
				t.Errorf("carrying the tunnel changed more than the encapsulation:\n--- carried ---\n%s\n--- plain ---\n%s",
					gotCarried, gotPlain)
			}
		})
	}
}

func TestL2tpOutEncapOnlyWhenCarried(t *testing.T) {
	peer := net.ParseIP("203.0.113.9").To4()

	plain := l2tpOutBuildSwanctlConn("tun", peer, 17020, "shared", false)
	carried := l2tpOutBuildSwanctlConn("tun", peer, 17020, "shared", true)

	if n := ipsecEncapCountLine(plain, ipsecEncapLine); n != 0 {
		t.Errorf("an uncarried tunnel forces UDP encapsulation (%d times):\n%s", n, plain)
	}
	if n := ipsecEncapCountLine(carried, ipsecEncapLine); n != 1 {
		t.Fatalf("a carried tunnel wrote %d encap lines, want exactly 1:\n%s", n, carried)
	}
	if !strings.Contains(carried, "\n        encap = yes\n") {
		t.Errorf("the encap line is not at connection level:\n%s", carried)
	}
	// IKEv1 is what L2TP/IPsec speaks everywhere, and encap has to sit in the same block
	// as `version = 1` for charon to fake the NAT-D payloads at all.
	if !strings.Contains(carried, "        version = 1\n") {
		t.Errorf("the L2TP leg stopped being IKEv1:\n%s", carried)
	}
	if got := strings.Replace(carried, "        encap = yes\n", "", 1); got != plain {
		t.Errorf("carrying the tunnel changed more than the encapsulation:\n--- carried ---\n%s\n--- plain ---\n%s",
			got, plain)
	}
}

// The fingerprint is the re-dial trigger. An operator who points an existing tunnel at an
// Xray outbound changes nothing in Settings, so a hash over Settings alone leaves Up
// returning early on the live tunnel: the old connection stays loaded, its ESP stays raw,
// and the carrier drops it while the panel reports the save as applied.
func TestIkev2OutFingerprintTracksCarriedness(t *testing.T) {
	s := ikev2EncapSettings()
	plain, carried := ikev2OutFingerprint(s, false), ikev2OutFingerprint(s, true)
	if plain == carried {
		t.Fatalf("carrying the tunnel did not move the fingerprint (%s), so Up would not re-dial", plain)
	}
	// Still a fingerprint of the settings: two tunnels that differ only in a password must
	// not collide just because carried-ness is now in the hash.
	other := ikev2EncapSettings()
	other.Password = "different"
	if ikev2OutFingerprint(other, true) == carried {
		t.Error("two different passwords hash the same when carried")
	}
	// And it is the same value the generated file records, or the stored-versus-computed
	// comparison in Up compares two different things and never matches.
	conf := ikev2OutBuildConnConf("tun", "ike-tun", 4242, s, true)
	if !strings.Contains(conf, ikev2OutFingerprintMark+carried+"\n") {
		t.Errorf("the connection file does not record the carried fingerprint %s:\n%s", carried, conf)
	}
}

func TestL2tpOutFingerprintTracksCarriedness(t *testing.T) {
	s := &l2tpOutSettings{Server: "203.0.113.9", Username: "account", Password: "hunter2", IpsecPsk: "shared"}
	plain, carried := l2tpOutFingerprint(s, false), l2tpOutFingerprint(s, true)
	if plain == carried {
		t.Fatalf("carrying the tunnel did not move the fingerprint (%s), so Up would not re-dial", plain)
	}
	other := &l2tpOutSettings{Server: "203.0.113.9", Username: "account", Password: "different", IpsecPsk: "shared"}
	if l2tpOutFingerprint(other, true) == carried {
		t.Error("two different passwords hash the same when carried")
	}
}

// Listings in the shape the bundled swanctl 5.9.14 prints. Its child line is formatted
// "  %s: #%s, reqid %s, %s, %s%s, %s:" and the sixth field is "-in-UDP" exactly when the
// vici attribute `encap` is yes, so the mode reads TUNNEL-in-UDP or TRANSPORT-in-UDP. This
// is the only place the human listing says it: `encap: yes` appears under --raw, which
// nothing in this package parses.
const (
	ikev2SasEncapsulated = `vpnout-ike-tun: #1, ESTABLISHED, IKEv2, 9c1fa0:8b2ec4
  local  'CN=client' @ 10.11.0.2[4500] [10.6.0.2]
  remote '203.0.113.9' @ 203.0.113.9[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  established 4s ago, rekeying in 13675s
  net: #1, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_GCM_16-128
    installed 4s ago, rekeying in 3388s, expires in 3956s
    in  c1a2b3c4, 0 bytes, 0 packets
    out d4e5f6a7, 0 bytes, 0 packets
    local  10.6.0.2/32
    remote 0.0.0.0/0
`

	ikev2SasRawEsp = `vpnout-ike-tun: #1, ESTABLISHED, IKEv2, 9c1fa0:8b2ec4
  local  'CN=client' @ 198.51.100.7[500] [10.6.0.2]
  remote '203.0.113.9' @ 203.0.113.9[500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  established 4s ago, rekeying in 13675s
  net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-128
    installed 4s ago, rekeying in 3388s, expires in 3956s
    local  10.6.0.2/32
    remote 0.0.0.0/0
`

	l2tpSasEncapsulated = `vpnout-l2tp-tun: #2, ESTABLISHED, IKEv1, 4d20aa:77b1cc
  local  '10.11.0.2' @ 10.11.0.2[4500]
  remote '203.0.113.9' @ 203.0.113.9[4500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  established 1s ago, rekeying in 10403s
  l2tp: #2, reqid 2, INSTALLED, TRANSPORT-in-UDP, ESP:AES_CBC-256/HMAC_SHA2_256_128
    installed 1s ago, rekeying in 3221s
    local  10.11.0.2/32[udp/17020]
    remote 203.0.113.9/32[udp/l2f]
`

	l2tpSasRawEsp = `vpnout-l2tp-tun: #2, ESTABLISHED, IKEv1, 4d20aa:77b1cc
  local  '198.51.100.7' @ 198.51.100.7[500]
  remote '203.0.113.9' @ 203.0.113.9[500]
  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
  established 1s ago, rekeying in 10403s
  l2tp: #2, reqid 2, INSTALLED, TRANSPORT, ESP:AES_CBC-256/HMAC_SHA2_256_128
    installed 1s ago, rekeying in 3221s
    local  198.51.100.7/32[udp/17020]
    remote 203.0.113.9/32[udp/l2f]
`
)

func TestIpsecOutEncapReadback(t *testing.T) {
	for name, tc := range map[string]struct {
		listing string
		want    bool
	}{
		"ikev2 floated to 4500":   {ikev2SasEncapsulated, true},
		"ikev2 raw esp":           {ikev2SasRawEsp, false},
		"l2tp transport in udp":   {l2tpSasEncapsulated, true},
		"l2tp raw esp":            {l2tpSasRawEsp, false},
		"no sa at all":            {"", false},
		"swanctl said no matches": {"no matching SAs found\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ipsecOutEncapInstalled(tc.listing); got != tc.want {
				t.Errorf("encapsulated=%v, want %v, for:\n%s", got, tc.want, tc.listing)
			}
		})
	}
}

// Both drivers declare themselves carriable, and the framework has to be able to ask.
// A driver that answered nothing would be taken as carriable anyway, so the assertion
// that matters is the interface being satisfied at all: it is what makes the answer this
// slice is responsible for reachable from vpnOutCarrierRefusal.
func TestIkev2AndL2tpAnswerCarriableOverProxy(t *testing.T) {
	for kind, cfg := range map[string]VpnOutboundConfig{
		VpnOutIKEv2: {
			Tag:      "ike",
			Kind:     VpnOutIKEv2,
			Settings: []byte(`{"server":"203.0.113.9","authMode":"eap-mschapv2","username":"a","password":"b"}`),
		},
		VpnOutL2TP: {
			Tag:      "l2tp",
			Kind:     VpnOutL2TP,
			Settings: []byte(`{"server":"203.0.113.9","username":"a","password":"b","ipsecPsk":"shared"}`),
		},
		VpnOutL2TP + "-plain": {
			// No pre-shared key: pure UDP 1701, nothing to encapsulate.
			Tag:      "l2tp-plain",
			Kind:     VpnOutL2TP,
			Settings: []byte(`{"server":"203.0.113.9","username":"a","password":"b"}`),
		},
	} {
		t.Run(kind, func(t *testing.T) {
			d, err := vpnOutDriverFor(cfg.Kind)
			if err != nil {
				t.Fatal(err)
			}
			ask, ok := d.(VpnOutCarriable)
			if !ok {
				t.Fatalf("%s does not implement VpnOutCarriable, so nothing forces its encapsulation", cfg.Kind)
			}
			can, why := ask.CarriableOverProxy(cfg)
			if !can {
				t.Fatalf("%s refuses a proxy carrier: %s", cfg.Kind, why)
			}
			if why != "" {
				t.Errorf("%s says yes and gives a reason anyway: %q", cfg.Kind, why)
			}
		})
	}
}
