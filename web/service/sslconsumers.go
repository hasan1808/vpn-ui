package service

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hasan1808/pro-ui/database/model"
)

// Who else on this host is serving the certificate, and what it takes to make
// them serve the NEW one.
//
// This is the part that was missing entirely, and its absence is why a renewed
// certificate silently stopped matching: the panel picked the new one up within
// ten seconds while charon kept presenting the copy it loaded at boot, so the same
// file produced a working panel and a failing VPN.
//
// The consumers split cleanly by cost, and that split is the whole design:
//
//	FREE, applied automatically, nobody notices
//	  panel + subscription listeners  re-read per handshake (cert_reloader.go), <=10s
//	  Xray path-mode, oneTimeLoading false  Xray re-reads within 3600s on its own
//	  IKEv2 / charon                   republish + `swanctl --load-all`; live SAs survive
//
//	DISRUPTIVE, never applied without being asked, every connected user drops
//	  ocserv                           reads its certificate at process start only
//	  SSTP / accel-ppp                 same, and the bundle ships no accel-cmd at all,
//	                                   so there is no runtime control socket to ask
//	  Xray path-mode, oneTimeLoading TRUE  the file is read once and cached forever
//
// DELIBERATELY OUT OF SCOPE, and the reasons are not "we ran out of time". Do not
// "fix" these later without reading why:
//
//   - OpenVPN. Its client verifies the server with `remote-cert-tls server`
//     (openvpn.go:887), which is an EXTENDED KEY USAGE check, not a name check, and
//     the generated profile EMBEDS its own CA (openvpn.go:919-921). Substituting a
//     public CA would mean ANY Let's Encrypt server certificate on the internet
//     satisfies the client's check. That is a security DOWNGRADE, not an upgrade.
//   - MTProto FakeTLS. It deliberately IMPERSONATES a domain it does not own
//     (mtproto.go, tls_domain / tls_emulation). A real certificate for a domain we
//     DO own defeats the entire point of the disguise.
//   - SSH host keys. Not TLS at all, and rotating one invalidates every client's
//     known_hosts entry, which is a support incident rather than a renewal.
type SSLConsumer struct {
	Kind       string `json:"kind"`
	Label      string `json:"label"`
	InboundId  int    `json:"inboundId,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Disruptive bool   `json:"disruptive"`

	// Action is what applying does, in words, so the UI can show the operator the
	// consequence before they agree to it.
	Action string `json:"action"`
}

const (
	SSLConsumerPanel  = "panel"
	SSLConsumerSub    = "subscription"
	SSLConsumerXray   = "xray"
	SSLConsumerIkev2  = "ikev2"
	SSLConsumerOcserv = "ocserv"
	SSLConsumerSstp   = "sstp"
)

// ListSSLConsumers finds everything configured to serve the given certificate
// path.
//
// Matching is on the EXACT configured path, not on where it resolves to. That is
// the contract: point a consumer at the store's stable active path and it takes
// part in the fan-out. A consumer pointed at a specific version directory is
// deliberately NOT matched, because re-pointing the active link does not change
// what that consumer serves, and telling the operator it did would be a lie.
func ListSSLConsumers(certPath string) ([]SSLConsumer, error) {
	want := filepath.Clean(certPath)
	var out []SSLConsumer

	var ss SettingService
	if p, err := ss.GetCertFile(); err == nil && filepath.Clean(p) == want {
		out = append(out, SSLConsumer{
			Kind: SSLConsumerPanel, Label: "Panel HTTPS listener",
			Action: "Nothing to do: the panel re-reads the certificate on the next handshake, within 10 seconds.",
		})
	}
	if p, err := ss.GetSubCertFile(); err == nil && filepath.Clean(p) == want {
		out = append(out, SSLConsumer{
			Kind: SSLConsumerSub, Label: "Subscription HTTPS listener",
			Action: "Nothing to do: the subscription listener re-reads the certificate on the next handshake, within 10 seconds.",
		})
	}

	var is InboundService
	inbounds, err := is.GetAllInbounds()
	if err != nil {
		return out, err
	}
	for _, in := range inbounds {
		if c, ok := sslConsumerForInbound(in, want); ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func sslConsumerForInbound(in *model.Inbound, want string) (SSLConsumer, bool) {
	switch in.Protocol {
	case "ikev2":
		var st struct {
			TlsUseFile      bool   `json:"tlsUseFile"`
			CertificateFile string `json:"certificateFile"`
		}
		if json.Unmarshal([]byte(in.Settings), &st) != nil || !st.TlsUseFile {
			return SSLConsumer{}, false
		}
		if filepath.Clean(strings.TrimSpace(st.CertificateFile)) != want {
			return SSLConsumer{}, false
		}
		return SSLConsumer{
			Kind: SSLConsumerIkev2, Label: fmt.Sprintf("IKEv2 inbound %q", in.Remark),
			InboundId: in.Id, Protocol: string(in.Protocol),
			// Republishing is NOT optional and a bare reload is NOT enough. In path
			// mode the panel COPIES the certificate into /etc/swanctl/x509 and the
			// key into /etc/swanctl/private (ikev2.go:523-528,571,607), because
			// swanctl auto-loads credentials only from its own directories. charon
			// therefore serves the COPY, and reloading without refreshing it just
			// reloads the stale one.
			Action: "Republish the certificate into the swanctl directories and run `swanctl --load-all`. Live tunnels are not affected.",
		}, true

	case "ocserv":
		var st struct {
			TlsUseFile      bool   `json:"tlsUseFile"`
			CertificateFile string `json:"certificateFile"`
		}
		if json.Unmarshal([]byte(in.Settings), &st) != nil || !st.TlsUseFile {
			return SSLConsumer{}, false
		}
		if filepath.Clean(strings.TrimSpace(st.CertificateFile)) != want {
			return SSLConsumer{}, false
		}
		return SSLConsumer{
			Kind: SSLConsumerOcserv, Label: fmt.Sprintf("OpenConnect inbound %q", in.Remark),
			InboundId: in.Id, Protocol: string(in.Protocol), Disruptive: true,
			Action: "Restart ocserv. It reads its certificate only at process start, so there is no cheaper option, and EVERY connected OpenConnect user is disconnected.",
		}, true

	case "sstp":
		var st struct {
			TlsUseFile      bool   `json:"tlsUseFile"`
			CertificateFile string `json:"certificateFile"`
		}
		if json.Unmarshal([]byte(in.Settings), &st) != nil || !st.TlsUseFile {
			return SSLConsumer{}, false
		}
		if filepath.Clean(strings.TrimSpace(st.CertificateFile)) != want {
			return SSLConsumer{}, false
		}
		return SSLConsumer{
			Kind: SSLConsumerSstp, Label: fmt.Sprintf("SSTP inbound %q", in.Remark),
			InboundId: in.Id, Protocol: string(in.Protocol), Disruptive: true,
			Action: "Restart accel-ppp. The bundle ships no accel-cmd, so there is no control socket to reload through, and EVERY connected SSTP user is disconnected.",
		}, true
	}

	// Everything else is an Xray inbound, where the certificate lives in
	// streamSettings.tlsSettings.certificates[].
	oneTime, matched := sslXrayCertMatch(in.StreamSettings, want)
	if !matched {
		return SSLConsumer{}, false
	}
	if oneTime {
		return SSLConsumer{
			Kind: SSLConsumerXray, Label: fmt.Sprintf("Xray inbound %q", in.Remark),
			InboundId: in.Id, Protocol: string(in.Protocol), Disruptive: true,
			Action: "Restart Xray. This inbound has \"one time loading\" enabled, which tells Xray to read the certificate once and cache it forever, so a renewed certificate is never picked up without a restart. Every Xray-routed connection drops.",
		}, true
	}
	return SSLConsumer{
		Kind: SSLConsumerXray, Label: fmt.Sprintf("Xray inbound %q", in.Remark),
		InboundId: in.Id, Protocol: string(in.Protocol),
		Action: "Nothing to do: Xray re-reads a file-mode certificate within an hour on its own.",
	}, true
}

// sslXrayCertMatch reports whether an inbound's stream settings reference the
// path, and whether that reference has oneTimeLoading set.
func sslXrayCertMatch(streamSettings, want string) (oneTimeLoading, matched bool) {
	if strings.TrimSpace(streamSettings) == "" {
		return false, false
	}
	var stream struct {
		TlsSettings struct {
			Certificates []struct {
				CertificateFile string `json:"certificateFile"`
				OneTimeLoading  bool   `json:"oneTimeLoading"`
			} `json:"certificates"`
		} `json:"tlsSettings"`
	}
	if json.Unmarshal([]byte(streamSettings), &stream) != nil {
		return false, false
	}
	for _, c := range stream.TlsSettings.Certificates {
		if filepath.Clean(strings.TrimSpace(c.CertificateFile)) == want {
			return c.OneTimeLoading, true
		}
	}
	return false, false
}

// SSLFanOutOptions controls how far the fan-out goes.
type SSLFanOutOptions struct {
	// ApplyDisruptive restarts the consumers that can only pick up a new
	// certificate by restarting, disconnecting their users. Default false: a
	// renewal is a background maintenance event and must not silently drop
	// everyone. The alternative is honest and usually correct: leave them serving
	// the old certificate until they next restart anyway.
	ApplyDisruptive bool `json:"applyDisruptive"`
}

// ApplySSLConsumers refreshes every consumer of the given certificate path.
//
// The free ones always run. The disruptive ones run only when asked, and when they
// are skipped that is reported as a step rather than passed over in silence: a
// consumer still serving the old certificate is exactly the state that produces
// "the certificate renewed but my VPN still shows the old one".
func ApplySSLConsumers(certPath string, opts SSLFanOutOptions, emit func(ProvisionStep)) {
	consumers, err := ListSSLConsumers(certPath)
	if err != nil {
		emit(ProvisionStep{Name: "consumers", Msg: "Could not list the services using this certificate: " + err.Error()})
		return
	}
	if len(consumers) == 0 {
		emit(ProvisionStep{Name: "consumers", OK: true, Msg: "Nothing on this host is configured to use this certificate path yet."})
		return
	}

	var ikev2Needed bool
	var xrayRestart bool
	var deferred []string

	for _, c := range consumers {
		switch {
		case c.Kind == SSLConsumerPanel || c.Kind == SSLConsumerSub:
			emit(ProvisionStep{Name: c.Label, OK: true, Msg: c.Action})

		case c.Kind == SSLConsumerXray && !c.Disruptive:
			emit(ProvisionStep{Name: c.Label, OK: true, Msg: c.Action})

		case c.Kind == SSLConsumerXray && c.Disruptive:
			if opts.ApplyDisruptive {
				xrayRestart = true
			} else {
				deferred = append(deferred, c.Label)
				emit(ProvisionStep{Name: c.Label, OK: true, Warn: true, Msg: "Skipped: " + c.Action})
			}

		case c.Kind == SSLConsumerIkev2:
			ikev2Needed = true

		case c.Kind == SSLConsumerOcserv:
			if !opts.ApplyDisruptive {
				deferred = append(deferred, c.Label)
				emit(ProvisionStep{Name: c.Label, OK: true, Warn: true, Msg: "Skipped: " + c.Action})
				continue
			}
			var oc OcservService
			err := oc.RestartServices()
			emit(ProvisionStep{Name: c.Label, OK: err == nil, Msg: sslApplyMsg(err, "Restarted ocserv with the new certificate. Connected users were disconnected.")})

		case c.Kind == SSLConsumerSstp:
			if !opts.ApplyDisruptive {
				deferred = append(deferred, c.Label)
				emit(ProvisionStep{Name: c.Label, OK: true, Warn: true, Msg: "Skipped: " + c.Action})
				continue
			}
			var sstp SstpService
			err := sstp.RestartServices()
			emit(ProvisionStep{Name: c.Label, OK: err == nil, Msg: sslApplyMsg(err, "Restarted accel-ppp with the new certificate. Connected users were disconnected.")})
		}
	}

	if ikev2Needed {
		sslRepublishIkev2(emit)
	}
	if xrayRestart {
		var xs XrayService
		err := xs.RestartXray(true)
		emit(ProvisionStep{Name: "Xray", OK: err == nil, Msg: sslApplyMsg(err, "Restarted Xray so the one-time-loading inbounds pick up the new certificate.")})
	}
	if len(deferred) > 0 {
		emit(ProvisionStep{Name: "not applied", OK: true, Warn: true, Msg: fmt.Sprintf(
			"%s still serve the PREVIOUS certificate and will keep doing so until they next restart. Re-run with \"apply to services that drop connections\" when a disconnection is acceptable.",
			strings.Join(deferred, ", "))})
	}
}

// sslRepublishIkev2 refreshes charon's own copies and reloads it.
//
// One republish and one reload for the whole host, not one per inbound: charon is
// SHARED with L2TP/IPsec (charon.go:314-330) and `swanctl --load-all` merges every
// conf.d file, so syncCharon is a host-level operation. Running it per inbound
// would reload charon N times for no benefit.
//
// GenerateAllConfigs is what re-runs writeCertFiles (ikev2.go:509) for every IKEv2
// inbound, which is what copies the renewed certificate into /etc/swanctl. Note
// what is NOT touched: ikev2Settings.CaCert. That field is OVERLOADED, holding the
// CLIENT-SIGNING CA in eap-tls mode (ikev2.go:549-556) and a server-chain addition
// otherwise (ikev2.go:534-536), so writing an issuer chain into it would break
// eap-tls client validation. Nothing here writes settings at all.
func sslRepublishIkev2(emit func(ProvisionStep)) {
	var ik Ikev2Service
	if err := ik.GenerateAllConfigs(); err != nil {
		emit(ProvisionStep{Name: "IKEv2 / charon", Msg: "Could not republish the certificate into the swanctl directories: " + err.Error()})
		return
	}
	if err := syncCharon(); err != nil {
		emit(ProvisionStep{Name: "IKEv2 / charon", Msg: "Republished the certificate but charon would not reload: " + err.Error()})
		return
	}
	emit(ProvisionStep{Name: "IKEv2 / charon", OK: true, Msg: "Republished the certificate into /etc/swanctl and reloaded charon. Live tunnels were not affected."})
}

func sslApplyMsg(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}
