package service

import (
	"testing"

	"github.com/hasan1808/pro-ui/database/model"
)

const testActiveCert = "/opt/vpn-ui/cert/managed/active/fullchain.pem"

func TestSSLConsumerClassification(t *testing.T) {
	cases := []struct {
		name           string
		inbound        *model.Inbound
		wantMatch      bool
		wantKind       string
		wantDisruptive bool
	}{
		{
			name: "ikev2 in path mode reloads without dropping anyone",
			inbound: &model.Inbound{
				Id: 1, Remark: "ike", Protocol: "ikev2",
				Settings: `{"tlsUseFile":true,"certificateFile":"` + testActiveCert + `"}`,
			},
			wantMatch: true, wantKind: SSLConsumerIkev2, wantDisruptive: false,
		},
		{
			// Content mode holds its own PEM and is not ours to touch.
			name: "ikev2 in content mode is not a consumer",
			inbound: &model.Inbound{
				Id: 2, Remark: "ike", Protocol: "ikev2",
				Settings: `{"tlsUseFile":false,"certificate":"-----BEGIN CERTIFICATE-----"}`,
			},
			wantMatch: false,
		},
		{
			name: "ocserv reads its certificate only at start, so it drops users",
			inbound: &model.Inbound{
				Id: 3, Remark: "oc", Protocol: "ocserv",
				Settings: `{"tlsUseFile":true,"certificateFile":"` + testActiveCert + `"}`,
			},
			wantMatch: true, wantKind: SSLConsumerOcserv, wantDisruptive: true,
		},
		{
			name: "sstp has no control socket at all, so it drops users",
			inbound: &model.Inbound{
				Id: 4, Remark: "sstp", Protocol: "sstp",
				Settings: `{"tlsUseFile":true,"certificateFile":"` + testActiveCert + `"}`,
			},
			wantMatch: true, wantKind: SSLConsumerSstp, wantDisruptive: true,
		},
		{
			name: "xray re-reads a file-mode certificate on its own",
			inbound: &model.Inbound{
				Id: 5, Remark: "vless", Protocol: "vless",
				StreamSettings: `{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"` + testActiveCert + `","keyFile":"/k","oneTimeLoading":false}]}}`,
			},
			wantMatch: true, wantKind: SSLConsumerXray, wantDisruptive: false,
		},
		{
			// oneTimeLoading tells Xray to read the file once and cache it
			// forever, so a renewal is never picked up without a restart.
			name: "xray with oneTimeLoading needs a restart",
			inbound: &model.Inbound{
				Id: 6, Remark: "vless-otl", Protocol: "vless",
				StreamSettings: `{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"` + testActiveCert + `","keyFile":"/k","oneTimeLoading":true}]}}`,
			},
			wantMatch: true, wantKind: SSLConsumerXray, wantDisruptive: true,
		},
		{
			name: "an inbound pointed somewhere else is not a consumer",
			inbound: &model.Inbound{
				Id: 7, Remark: "other", Protocol: "vless",
				StreamSettings: `{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/etc/other/fullchain.pem"}]}}`,
			},
			wantMatch: false,
		},
		{
			// A consumer pinned to one version does not follow the active link, so
			// claiming it was refreshed would be a lie.
			name: "an inbound pinned to a version directory is not a consumer",
			inbound: &model.Inbound{
				Id: 8, Remark: "pinned", Protocol: "vless",
				StreamSettings: `{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/opt/vpn-ui/cert/managed/versions/example.com-abcd1234/20260804T120000Z-aabb/fullchain.pem"}]}}`,
			},
			wantMatch: false,
		},
		{
			name: "reality has no certificates",
			inbound: &model.Inbound{
				Id: 9, Remark: "reality", Protocol: "vless",
				StreamSettings: `{"security":"reality","realitySettings":{"dest":"example.com:443"}}`,
			},
			wantMatch: false,
		},
		{
			name:      "malformed settings must not panic or match",
			inbound:   &model.Inbound{Id: 10, Remark: "broken", Protocol: "ikev2", Settings: `{not json`},
			wantMatch: false,
		},
		{
			// OpenVPN is deliberately out of scope: its client checks the EKU, not
			// the name, and the profile embeds its own CA, so a public certificate
			// is a security downgrade.
			name: "openvpn is never a consumer",
			inbound: &model.Inbound{
				Id: 11, Remark: "ovpn", Protocol: "openvpn",
				Settings: `{"tlsUseFile":true,"certificateFile":"` + testActiveCert + `"}`,
			},
			wantMatch: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sslConsumerForInbound(tc.inbound, testActiveCert)
			if ok != tc.wantMatch {
				t.Fatalf("matched = %v, want %v (%+v)", ok, tc.wantMatch, got)
			}
			if !tc.wantMatch {
				return
			}
			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q", got.Kind, tc.wantKind)
			}
			if got.Disruptive != tc.wantDisruptive {
				t.Errorf("Disruptive = %v, want %v", got.Disruptive, tc.wantDisruptive)
			}
			if got.Action == "" {
				t.Error("every consumer must say what applying does, so the UI can warn before it drops anyone")
			}
			if got.InboundId != tc.inbound.Id {
				t.Errorf("InboundId = %d, want %d", got.InboundId, tc.inbound.Id)
			}
		})
	}
}

func TestSSLXrayCertMatch(t *testing.T) {
	cases := []struct {
		name        string
		stream      string
		wantMatch   bool
		wantOneTime bool
	}{
		{"empty", "", false, false},
		{"not json", "{{{", false, false},
		{"no tls block", `{"network":"tcp"}`, false, false},
		{"empty certificate list", `{"tlsSettings":{"certificates":[]}}`, false, false},
		{
			"second certificate in the list still matches",
			`{"tlsSettings":{"certificates":[{"certificateFile":"/other.pem"},{"certificateFile":"` + testActiveCert + `","oneTimeLoading":true}]}}`,
			true, true,
		},
		{
			"an unclean but equivalent path matches",
			`{"tlsSettings":{"certificates":[{"certificateFile":"/opt/vpn-ui/cert/managed/./active/fullchain.pem"}]}}`,
			true, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oneTime, matched := sslXrayCertMatch(tc.stream, testActiveCert)
			if matched != tc.wantMatch {
				t.Fatalf("matched = %v, want %v", matched, tc.wantMatch)
			}
			if matched && oneTime != tc.wantOneTime {
				t.Errorf("oneTimeLoading = %v, want %v", oneTime, tc.wantOneTime)
			}
		})
	}
}
