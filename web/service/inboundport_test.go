package service

import (
	"net"
	"strconv"
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

func claimSet(claims []portClaim) map[portClaim]bool {
	out := make(map[portClaim]bool, len(claims))
	for _, c := range claims {
		out[portClaim{port: c.port, network: c.network}] = true
	}
	return out
}

// The protocols whose row port is not a socket must claim nothing, because a probe
// of a bookkeeping number rejects a save for a conflict that does not exist.
func TestInboundPortClaimsSkipsNonBindingProtocols(t *testing.T) {
	for _, protocol := range []model.Protocol{model.GRE, model.L2TP, model.PPTP, model.IKEV2} {
		in := &model.Inbound{Protocol: protocol, Port: 1701, Enable: true}
		if got := inboundPortClaims(in); len(got) != 0 {
			t.Errorf("%s claimed %v, want none: its listening port is not the one in the row", protocol, got)
		}
	}
}

func TestInboundPortClaimsNetworkPerProtocol(t *testing.T) {
	tests := []struct {
		protocol model.Protocol
		want     string
	}{
		{model.WGC, "udp"},
		{model.AWG, "udp"},
		{model.TUIC, "udp"},
		{model.SSTP, "tcp"},
		{model.SSH, "tcp"},
		{model.MTPROTO, "tcp"},
		{model.ANYTLS, "tcp"},
		{model.OPENCONNECT, "tcp"},
	}
	for _, tc := range tests {
		in := &model.Inbound{Protocol: tc.protocol, Port: 4000, Enable: true}
		claims := inboundPortClaims(in)
		if len(claims) != 1 {
			t.Fatalf("%s: got %d claims, want 1", tc.protocol, len(claims))
		}
		if claims[0].network != tc.want {
			t.Errorf("%s binds %s, want %s", tc.protocol, claims[0].network, tc.want)
		}
	}
}

// mKCP and QUIC are datagram transports, so an Xray inbound on one competes for UDP,
// not TCP. Getting this backwards would both miss real clashes and invent fake ones.
func TestInboundPortClaimsXrayTransportPicksNetwork(t *testing.T) {
	tests := map[string]string{
		`{"network":"tcp"}`:         "tcp",
		`{"network":"ws"}`:          "tcp",
		`{"network":"xhttp"}`:       "tcp",
		`{"network":"grpc"}`:        "tcp",
		`{"network":"kcp"}`:         "udp",
		`{"network":"quic"}`:        "udp",
		``:                          "tcp",
		`{"network":"httpupgrade"}`: "tcp",
	}
	for stream, want := range tests {
		in := &model.Inbound{Protocol: model.VLESS, Port: 4001, Enable: true, StreamSettings: stream}
		claims := inboundPortClaims(in)
		if len(claims) != 1 {
			t.Fatalf("stream %q: got %d claims, want 1", stream, len(claims))
		}
		if claims[0].network != want {
			t.Errorf("stream %q binds %s, want %s", stream, claims[0].network, want)
		}
	}
}

// OpenVPN is the reason a claim list exists at all: its TCP instance can sit on a
// second port that lives in the settings JSON, where the port column cannot see it.
func TestInboundPortClaimsOpenvpnBothTransports(t *testing.T) {
	in := &model.Inbound{
		Protocol: model.OPENVPN,
		Port:     1195,
		Enable:   true,
		Settings: `{"udpEnable":true,"tcpEnable":true,"separatePorts":true,"tcpPort":1194}`,
	}
	got := claimSet(inboundPortClaims(in))
	for _, want := range []portClaim{{port: 1195, network: "udp"}, {port: 1194, network: "tcp"}} {
		if !got[want] {
			t.Errorf("missing claim %v, got %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("got %d claims, want 2: %v", len(got), got)
	}
}

// Sharing one port between the two transports is legal, so it must not be reported
// as a self-conflict.
func TestInboundPortClaimsOpenvpnSharedPort(t *testing.T) {
	in := &model.Inbound{
		Protocol: model.OPENVPN,
		Port:     1195,
		Enable:   true,
		Settings: `{"udpEnable":true,"tcpEnable":true,"separatePorts":false,"tcpPort":1194}`,
	}
	got := claimSet(inboundPortClaims(in))
	for _, want := range []portClaim{{port: 1195, network: "udp"}, {port: 1195, network: "tcp"}} {
		if !got[want] {
			t.Errorf("missing claim %v, got %v", want, got)
		}
	}
}

func TestInboundPortClaimsOpenvpnDisabledTransport(t *testing.T) {
	in := &model.Inbound{
		Protocol: model.OPENVPN,
		Port:     1195,
		Enable:   true,
		Settings: `{"udpEnable":false,"tcpEnable":true,"separatePorts":true,"tcpPort":1194}`,
	}
	claims := inboundPortClaims(in)
	if len(claims) != 1 || claims[0].port != 1194 || claims[0].network != "tcp" {
		t.Fatalf("got %v, want only the TCP port: UDP is switched off", claims)
	}
}

func TestListenOverlaps(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"", "10.0.0.1", true},
		{"0.0.0.0", "10.0.0.1", true},
		{"::", "10.0.0.1", true},
		{"10.0.0.1", "10.0.0.1", true},
		{"10.0.0.1", "10.0.0.2", false},
	}
	for _, tc := range tests {
		if got := listenOverlaps(tc.a, tc.b); got != tc.want {
			t.Errorf("listenOverlaps(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// The probe has to answer yes only for a port that is genuinely held, on the network
// that holds it: a TCP listener says nothing about the same UDP port.
func TestPortInUseDetectsLiveListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback port here: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	if inUse, _ := portInUse("tcp", "127.0.0.1", port); !inUse {
		t.Errorf("port %d holds a live TCP listener but the probe called it free", port)
	}
	if inUse, _ := portInUse("udp", "127.0.0.1", port); inUse {
		t.Errorf("port %d is only bound on TCP; the UDP probe must not claim a conflict", port)
	}
}

func TestPortInUseFreePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback port here: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close()

	if inUse, _ := portInUse("tcp", "127.0.0.1", port); inUse {
		t.Errorf("port %d was just released but the probe still calls it taken", port)
	}
}

// A wildcard-listening inbound competes with a listener bound to one address only,
// because binding 0.0.0.0 over an in-use 127.0.0.1 is refused by the kernel.
func TestPortInUseWildcardSeesLoopbackListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a loopback port here: %v", err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	if inUse, _ := portInUse("tcp", probeHost("0.0.0.0"), port); !inUse {
		t.Errorf("a wildcard bind of port %d cannot succeed while loopback holds it, "+
			"so the probe must report the conflict", port)
	}
}
