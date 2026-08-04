package service

import (
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// The point of the server-side settings defaults: a MINIMAL API body creates a
// working inbound, instead of the caller having to hand-reproduce whatever
// web/assets/js/model/inbound.js emits for that protocol.
//
// Before this, the Go side took the settings blob verbatim with no defaults and
// no validation, so an external script could only create an l2tp, openvpn, wg-c
// or ikev2 inbound by guessing every field name and default the browser uses.
//
// Clients are seeded DISABLED because AddInbound pushes enabled ones to a live
// Xray over gRPC, which the test harness has no core for (see newInboundDB).
func TestMinimalApiCreatePerProtocol(t *testing.T) {
	svc := newInboundDB(t)
	cases := []struct {
		protocol model.Protocol
		port     int
		settings string
	}{
		{model.VLESS, 25201, `{"clients":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","email":"a1","enable":false}]}`},
		{model.L2TP, 25202, `{"clients":[{"id":"u1","password":"pw","email":"a2","enable":false}]}`},
		{model.PPTP, 25203, `{"clients":[{"id":"u2","password":"pw","email":"a3","enable":false}]}`},
		{model.WGC, 25205, `{"clients":[{"id":"a5","email":"a5","enable":false}]}`},
		{model.SSH, 25207, `{"clients":[{"id":"u5","password":"pw","email":"a7","enable":false}]}`},
		{model.MTPROTO, 25208, `{"clients":[{"id":"a8","email":"a8","secret":"0123456789abcdef0123456789abcdef","enable":false}]}`},
		{model.GRE, 25209, `{"clients":[{"id":"a9","email":"a9","enable":false}]}`},
		{model.OPENCONNECT, 25210, `{"clients":[{"id":"u6","password":"pw","email":"a10","enable":false}]}`},
		{model.AWG, 25212, `{"clients":[{"id":"a12","email":"a12","enable":false}]}`},
		{model.ANYTLS, 25213, `{"clients":[{"password":"pw","email":"a13","enable":false}]}`},
		{model.TUIC, 25214, `{"clients":[{"id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","password":"pw","email":"a14","enable":false}]}`},
		{model.NAIVE, 25215, `{"clients":[{"password":"pw","email":"a15","enable":false}]}`},
	}
	for _, tc := range cases {
		t.Run(string(tc.protocol), func(t *testing.T) {
			in := &model.Inbound{
				UserId: 1, Remark: "t-" + string(tc.protocol), Port: tc.port,
				Protocol: tc.protocol, Enable: true, Settings: tc.settings,
				Tag: "inbound-" + string(tc.protocol),
			}
			if _, _, err := svc.AddInbound(in); err != nil {
				t.Fatalf("minimal API create failed: %v", err)
			}
		})
	}
}

// openvpn, ikev2 and sstp are TLS servers and genuinely cannot be created
// without a certificate. That is a real requirement rather than a gap in the
// defaults, so it is pinned here: the refusal must be an explanatory error and
// not a half-created inbound that fails later at daemon start.
func TestMinimalApiCreateRequiresCertificateForTlsProtocols(t *testing.T) {
	svc := newInboundDB(t)
	cases := []struct {
		protocol model.Protocol
		port     int
		settings string
	}{
		{model.OPENVPN, 25304, `{"clients":[{"id":"u3","password":"pw","email":"b1","enable":false}]}`},
		{model.IKEV2, 25306, `{"clients":[{"id":"u4","password":"pw","email":"b2","enable":false}]}`},
		{model.SSTP, 25311, `{"clients":[{"id":"u7","password":"pw","email":"b3","enable":false}]}`},
	}
	for _, tc := range cases {
		t.Run(string(tc.protocol), func(t *testing.T) {
			in := &model.Inbound{
				UserId: 1, Remark: "t-" + string(tc.protocol), Port: tc.port,
				Protocol: tc.protocol, Enable: true, Settings: tc.settings,
				Tag: "inbound-" + string(tc.protocol),
			}
			_, _, err := svc.AddInbound(in)
			if err == nil {
				t.Fatal("created without a certificate: the daemon would fail to start later, with nothing pointing at the cause")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "certificate") {
				t.Errorf("the refusal must name the certificate as the cause; got: %v", err)
			}
		})
	}
}
