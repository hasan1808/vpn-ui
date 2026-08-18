package service

import (
	"strings"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

// tls-crypt is optional in OpenVPN, so a profile must be generatable without one,
// and the directive must be absent rather than present-and-empty: `tls-crypt` with
// no argument makes openvpn refuse the whole config, which is how a file-mode
// inbound with a blank key box turned into a daemon that never came up.

func ovpnInboundFor(settings string) *model.Inbound {
	return &model.Inbound{
		Id: 1, Protocol: model.OPENVPN, Port: 1195, Enable: true, Settings: settings,
	}
}

const ovpnTestCA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
const ovpnTestTC = "-----BEGIN OpenVPN Static key V1-----\nabcdef\n-----END OpenVPN Static key V1-----"

func TestOpenVpnClientConfigOmitsTlsCryptWhenDisabled(t *testing.T) {
	s := &OpenVpnService{}
	in := ovpnInboundFor(`{"udpEnable":true,"tcpEnable":false,"tlsCryptEnable":false,` +
		`"caCert":"` + strings.ReplaceAll(ovpnTestCA, "\n", `\n`) + `"}`)

	cfg, err := s.GenerateClientConfig(in, "udp", "vpn.example")
	if err != nil {
		t.Fatalf("a profile with tls-crypt switched off must still generate: %v", err)
	}
	if strings.Contains(cfg, "tls-crypt") {
		t.Errorf("the profile still carries a <tls-crypt> block with tls-crypt off:\n%s", cfg)
	}
	if !strings.Contains(cfg, "<ca>") {
		t.Error("the CA block is not optional and went missing")
	}
}

// With it ON the key is genuinely required: silently handing out a profile with an
// empty <tls-crypt> block would produce a client that cannot connect and no error
// anywhere saying why.
func TestOpenVpnClientConfigRequiresTlsCryptWhenEnabled(t *testing.T) {
	s := &OpenVpnService{}
	in := ovpnInboundFor(`{"udpEnable":true,"tcpEnable":false,"tlsCryptEnable":true,` +
		`"caCert":"` + strings.ReplaceAll(ovpnTestCA, "\n", `\n`) + `"}`)

	_, err := s.GenerateClientConfig(in, "udp", "vpn.example")
	if err == nil {
		t.Fatal("tls-crypt is on with no key, so the profile must be refused rather than shipped empty")
	}
	if !strings.Contains(err.Error(), "TLS-Crypt") {
		t.Errorf("the refusal does not name the field the operator has to fix: %v", err)
	}
}

// An inbound stored before the toggle existed carries no tlsCryptEnable key at all,
// and every one of those has a key and clients that already trust it. Absent has to
// read as ON, or an upgrade would drop the wrapper out from under them.
func TestOpenVpnClientConfigTreatsAbsentToggleAsEnabled(t *testing.T) {
	s := &OpenVpnService{}
	in := ovpnInboundFor(`{"udpEnable":true,"tcpEnable":false,` +
		`"caCert":"` + strings.ReplaceAll(ovpnTestCA, "\n", `\n`) + `",` +
		`"tlsCrypt":"` + strings.ReplaceAll(ovpnTestTC, "\n", `\n`) + `"}`)

	cfg, err := s.GenerateClientConfig(in, "udp", "vpn.example")
	if err != nil {
		t.Fatalf("a legacy inbound must keep generating: %v", err)
	}
	if !strings.Contains(cfg, "<tls-crypt>") {
		t.Errorf("a legacy inbound lost its tls-crypt block:\n%s", cfg)
	}
}

// FRIENDLY_NAME is what OpenVPN Connect lists the imported profile under.
func TestOpenVpnClientConfigWritesFriendlyName(t *testing.T) {
	s := &OpenVpnService{}
	in := ovpnInboundFor(`{"udpEnable":true,"tcpEnable":false,"tlsCryptEnable":false,` +
		`"friendlyName":"My Office VPN",` +
		`"caCert":"` + strings.ReplaceAll(ovpnTestCA, "\n", `\n`) + `"}`)

	cfg, err := s.GenerateClientConfig(in, "udp", "vpn.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, `setenv FRIENDLY_NAME "My Office VPN"`) {
		t.Errorf("the profile name is missing or unquoted (a name with a space would end the directive early):\n%s", cfg)
	}
}

func TestOpenVpnClientConfigOmitsAnEmptyFriendlyName(t *testing.T) {
	s := &OpenVpnService{}
	in := ovpnInboundFor(`{"udpEnable":true,"tcpEnable":false,"tlsCryptEnable":false,"friendlyName":"   ",` +
		`"caCert":"` + strings.ReplaceAll(ovpnTestCA, "\n", `\n`) + `"}`)

	cfg, err := s.GenerateClientConfig(in, "udp", "vpn.example")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, "FRIENDLY_NAME") {
		t.Errorf("a blank name produced an empty directive instead of none:\n%s", cfg)
	}
}

// A quote or a newline in the name would close the directive early or split the
// config into two, so they are stripped rather than escaped.
func TestOpenVpnFriendlyNameCannotBreakTheDirective(t *testing.T) {
	o := &openvpnSettings{FriendlyName: "  ev\"il\nname\\  "}
	got := o.friendlyName()
	for _, bad := range []string{`"`, "\n", `\`} {
		if strings.Contains(got, bad) {
			t.Errorf("friendlyName() = %q, still carries %q", got, bad)
		}
	}
	if got != "evilname" {
		t.Errorf("friendlyName() = %q, want %q", got, "evilname")
	}
}

// The server config is the other half: with no key there must be no directive,
// because `tls-crypt` alone on a line makes openvpn refuse the entire file.
func TestOpenVpnServerConfigOmitsTlsCryptWithNoKey(t *testing.T) {
	s := &OpenVpnService{}
	in := ovpnInboundFor(`{"udpEnable":true,"tcpEnable":false,"tlsUseFile":true,` +
		`"caCertFile":"/etc/ca.crt","serverCertFile":"/etc/s.crt","serverKeyFile":"/etc/s.key",` +
		`"tlsCryptFile":"","tlsCryptEnable":false}`)
	settings, err := s.parseSettings(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.buildServerConfig(in, settings, "udp", 1195, "/usr/local/bin/vpn-ui")
	for _, line := range strings.Split(cfg, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "tls-crypt") {
			t.Errorf("server config carries %q with no key to point it at", line)
		}
	}
	if !strings.Contains(cfg, "ca /etc/ca.crt") {
		t.Errorf("the operator's own CA path did not reach the config:\n%s", cfg)
	}
}
