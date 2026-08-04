package xray

import (
	"strings"
	"testing"
)

// Init is allowed to fail (Xray not running, API port 0, dial refused) and every
// caller in web/service ignores that error, so these four can be reached with no
// client at all.
//
// They used to dereference *x.HandlerServiceClient straight away. That does not
// return an error, it panics, and it panics on the request goroutine, so the
// whole PANEL process dies. Worse, it is reachable in exactly the situation an
// operator is most likely to be clicking around in: a core that refused its
// config and is not up. Adding an inbound then killed the panel instead of
// reporting that Xray was unreachable.
func TestHandlerMethodsReportInsteadOfPanicWhenNotConnected(t *testing.T) {
	cases := []struct {
		name string
		call func(x *XrayAPI) error
	}{
		{"AddInbound", func(x *XrayAPI) error { return x.AddInbound([]byte(`{"tag":"t"}`)) }},
		{"DelInbound", func(x *XrayAPI) error { return x.DelInbound("t") }},
		{"AddUser", func(x *XrayAPI) error {
			return x.AddUser("vmess", "t", map[string]any{"email": "e", "id": "i"})
		}},
		{"RemoveUser", func(x *XrayAPI) error { return x.RemoveUser("t", "e") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s PANICKED with no API connection (%v): this kills the panel process", tc.name, r)
				}
			}()
			x := &XrayAPI{} // never Init'd, exactly as after a failed connect
			err := tc.call(x)
			if err == nil {
				t.Fatalf("%s returned no error with no API connection", tc.name)
			}
			if !strings.Contains(err.Error(), "not connected") {
				t.Errorf("%s error should say the api is not connected; got: %v", tc.name, err)
			}
		})
	}
}

// Init must refuse a port it cannot dial rather than leaving a half-built client
// behind, which is the state the guards above exist to catch.
func TestInitRefusesInvalidPort(t *testing.T) {
	x := &XrayAPI{}
	if err := x.Init(0); err == nil {
		t.Fatal("Init(0) returned no error")
	}
	if x.HandlerServiceClient != nil {
		t.Error("Init left a handler client behind after refusing")
	}
}

// GetAPIPort is called through a package global that is nil until a core has
// started, and only about half its call sites in web/service check that first.
// A nil deref there is not a failed request, it kills the panel process.
func TestGetAPIPortIsNilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GetAPIPort PANICKED on a nil process (%v): this kills the panel", r)
		}
	}()
	var p *Process
	if got := p.GetAPIPort(); got != 0 {
		t.Errorf("GetAPIPort() = %d on a nil process, want 0 so Init refuses it before dialling", got)
	}
}
