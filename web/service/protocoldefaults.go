package service

import (
	"encoding/json"
	"strings"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/util/random"
)

// Server-side settings defaults and validation for the 14 non-Xray protocols.
//
// Every one of those protocols has its inbound `settings` JSON built ENTIRELY in the
// browser, by the classes in web/assets/js/model/inbound.js (Inbound.L2tpSettings,
// Inbound.WgcSettings, ...). The Go API used to take that blob verbatim: no defaults,
// no validation. A script calling POST /panel/api/inbounds/add therefore had to
// hand-reproduce the JS output field for field, and a key it guessed wrong was not an
// error, it was a daemon that came up with the wrong DNS / MTU / device cap, or an
// inbound whose settings the protocol's own Go struct could not even unmarshal.
//
// The tables below are a port of those JS classes: the same keys, the same defaults,
// read off each class's CONSTRUCTOR (which is what Inbound.Settings.getSettings runs
// for a NEW inbound, i.e. what the panel's own Add form starts from). Where a class's
// static fromJson() disagrees with its constructor the constructor wins, and the
// difference is called out at the field.
//
// web/assets/js/model/inbound.js is the spec. A key spelled differently here is silent
// breakage: the value lands in the stored JSON under a name nothing reads, the
// protocol's Go struct falls back to its zero value, and no error is raised anywhere.

// settingDefault is one settings key and the value a freshly created inbound of that
// protocol carries for it.
//
// mint, when set, produces the value per call instead of sharing one constant: the two
// IPsec pre-shared keys must not be identical across every inbound the panel ever
// creates, which is exactly what a package-level constant would give them.
type settingDefault struct {
	key  string
	val  any
	mint func() any
}

func def(key string, val any) settingDefault { return settingDefault{key: key, val: val} }

func gen(key string, mint func() any) settingDefault {
	return settingDefault{key: key, mint: mint}
}

func (d settingDefault) value() any {
	if d.mint != nil {
		return d.mint()
	}
	return d.val
}

// emptyList is the value of every array-valued default. A distinct []any{} per call so
// two inbounds can never end up sharing one backing slice through the marshaller.
func emptyList() any { return []any{} }

// noClients is the `clients` default. A fresh inbound gets NO accounts even though the
// JS constructors seed one: the browser can mint a credential locally, but an account
// created here would be one the caller never asked for and never sees the password of.
func noClients() any { return []any{} }

// protocolSettingDefaults returns the ordered settings defaults for a protocol, or nil
// for one that has none (every Xray-native protocol: the core owns those shapes and
// GenXrayInboundConfig passes them through untouched, so inventing keys for them here
// would only corrupt configs the core already understands).
//
// Order is the order of the matching JS toJson(), so this reads as a diff against the
// spec. It does not survive into the stored JSON (Go marshals map keys sorted, which is
// what AddInbound's own re-marshal already does to a UI-created inbound).
func protocolSettingDefaults(protocol model.Protocol) []settingDefault {
	switch protocol {
	case model.L2TP:
		// Inbound.L2tpSettings
		return []settingDefault{
			def("ipsecEnable", true),
			// RandomUtil.randomSeq(16) in the constructor. fromJson() passes an absent
			// psk straight through as undefined instead, so only a NEW inbound gets one.
			//
			// INHERITED, not minted, when an enabled l2tp inbound already has a key. A
			// fresh random key for a second inbound is not a risk of being rejected, it
			// is a certainty: CheckSharedDaemonConflicts refuses two different keys on
			// one IKE listen address, and a new inbound listens on all of them. The
			// operator was left hand-copying the first inbound's key out of the other
			// form. Minting only happens for the first l2tp inbound, or when the
			// existing ones have IPsec off. See sharedL2tpIpsecPsk.
			gen("ipsecPsk", func() any {
				if psk := sharedL2tpIpsecPsk(); psk != "" {
					return psk
				}
				return random.Seq(16)
			}),
			def("allowRaw", false),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			def("mtu", 1400),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
		}

	case model.PPTP:
		// Inbound.PptpSettings. No IPsec pair: PPTP carries MPPE itself.
		return []settingDefault{
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			def("mtu", 1400),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
		}

	case model.OPENVPN:
		// Inbound.OpenvpnSettings
		return []settingDefault{
			def("udpEnable", true),
			def("tcpEnable", true),
			def("tcpPort", 1194),
			// The one field where the JS constructor (false: TCP and UDP share
			// inbound.Port) and fromJson (true: TCP gets its own tcpPort) disagree. The
			// constructor is what the Add form starts from, so it is what a caller who
			// omits the key gets, and it is also the reading that cannot collide with
			// another inbound already holding 1194.
			def("separatePorts", false),
			def("tlsUseFile", false),
			def("caCertFile", ""),
			def("serverCertFile", ""),
			def("serverKeyFile", ""),
			def("tlsCryptFile", ""),
			// On by default: it is what every existing inbound does, and the
			// self-signed generator mints the key anyway. Turning it off is the
			// opt-out for an operator who does not want tls-crypt at all.
			def("tlsCryptEnable", true),
			// The .ovpn profile name (setenv FRIENDLY_NAME). Empty = emit nothing.
			def("friendlyName", ""),
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			def("mtu", 1500),
			// No cert is minted here. Generating one is client-side only (the JS forge
			// build), and validateInboundConfig already refuses an OpenVPN inbound with
			// no caCert/serverCert, so an API caller must still supply or generate a
			// certificate. Defaulting these to "" only makes the omission explicit.
			def("caCert", ""),
			def("caKey", ""),
			def("serverCert", ""),
			def("serverKey", ""),
			def("tlsCrypt", ""),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
			def("cipherMode", "all"),
			// Inbound.OpenvpnSettings.CIPHER_MODES.all, in its preference order: that
			// order is written straight into the `data-ciphers` directive.
			def("ciphers", []string{
				"AES-256-GCM",
				"AES-128-GCM",
				"CHACHA20-POLY1305",
				"AES-256-CBC",
				"AES-192-CBC",
				"AES-128-CBC",
				"BF-CBC",
				"DES-EDE3-CBC",
			}),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case model.OPENCONNECT:
		// Inbound.OcservSettings
		return []settingDefault{
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			def("mtu", 1420),
			def("tlsUseFile", false),
			def("certificateFile", ""),
			def("keyFile", ""),
			def("certificate", ""),
			def("key", ""),
			def("caCert", ""),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case model.SSTP:
		// Inbound.SstpSettings. Field for field identical to OcservSettings apart from the
		// MTU below; kept spelled out rather than shared so a future divergence in either
		// one cannot silently rewrite the other's stored JSON.
		return []settingDefault{
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			// 1400, and NOT OpenConnect's 1420. SSTP is PPP inside a 4-byte SSTP header
			// inside TLS inside TCP, so a 1500 byte path pays 20 (IP) + 20 (TCP) + 5 (TLS
			// record) + 16 (IV) + 32 (MAC) + 4 (SSTP) + 4 (PPP) and lands just under 1400.
			// OpenConnect's 1420 is a DTLS/UDP number and does not transfer.
			//
			// This also un-deadens two pieces of the codebase that already assumed 1400:
			// sstp.go's own writer falls back to 1400 when no MTU is set, and
			// vpnout_sstp.go picks 1400 with the comment "the value the panel's own SSTP
			// server uses" -- which was false while the form posted 1420 on every save.
			def("mtu", 1400),
			def("tlsUseFile", false),
			def("certificateFile", ""),
			def("keyFile", ""),
			def("certificate", ""),
			def("key", ""),
			def("caCert", ""),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case model.IKEV2:
		// Inbound.Ikev2Settings
		return []settingDefault{
			def("dns1", "8.8.8.8"),
			def("dns2", "8.8.4.4"),
			// ikev2DefaultMtu. 1400 because a real-world IKEv2 client is behind a NAT and
			// therefore carrying ESP inside UDP, which costs 73-100 bytes on a 1500 byte
			// path; the 1420 this used to say is the WireGuard figure and does not
			// transfer. The value is enforced as a TCP MSS clamp, not written into a
			// daemon config -- see ikev2Settings.Mtu for why that is the only option.
			def("mtu", ikev2DefaultMtu),
			def("authMode", "eap-mschapv2"),
			def("psk", ""),
			// Empty means "use the panel-access host / detected server IP", which is
			// what ikev2Settings documents. Not defaulted to anything guessable: the
			// value has to match the server cert's SAN or every client rejects it.
			def("serverAddr", ""),
			def("nattPort", 4500),
			def("tlsUseFile", false),
			def("certificateFile", ""),
			def("keyFile", ""),
			def("certificate", ""),
			def("key", ""),
			def("caCert", ""),
			def("clients", noClients()),
			def("externalProxy", emptyList()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case model.WGC:
		// Inbound.WgcSettings. Note the DNS pair differs from the PPP family (1.1.1.1
		// rather than 8.8.8.8); it is written into the generated client config.
		return []settingDefault{
			def("dns1", "1.1.1.1"),
			def("dns2", "1.0.0.1"),
			def("mtu", 1420),
			// Left empty on purpose: WgcService.ReconcileKeys mints the server keypair
			// (and every per-device keypair) after the inbound is stored. A key minted
			// here would be overwritten by it anyway.
			def("serverPrivKey", ""),
			def("serverPubKey", ""),
			def("pskEnable", false),
			def("clients", noClients()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("externalProxy", emptyList()),
		}

	case model.AWG:
		// Inbound.AwgSettings: WgcSettings plus the AWG 1.0 obfuscation parameters.
		// Jc/Jmin/Jmax/S1/S2 are the AmneziaWG defaults; the magic headers H1-H4 are
		// minted by AwgService (like serverPubKey) and start empty.
		return []settingDefault{
			def("dns1", "1.1.1.1"),
			def("dns2", "1.0.0.1"),
			def("mtu", 1420),
			def("jc", 4),
			def("jmin", 8),
			def("jmax", 80),
			def("s1", 77),
			def("s2", 90),
			def("h1", ""),
			def("h2", ""),
			def("h3", ""),
			def("h4", ""),
			def("serverPrivKey", ""),
			def("serverPubKey", ""),
			def("pskEnable", false),
			def("clients", noClients()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("externalProxy", emptyList()),
		}

	case model.GRE:
		// Inbound.GreSettings
		return []settingDefault{
			// 0 = let the kernel choose. The right value differs per encapsulation
			// (1476 raw, 1464 under FOU) and the kernel already knows which, so any
			// number pinned here would be wrong for the other mode.
			def("mtu", 0),
			def("ttl", 64),
			def("ipsecEnable", false),
			// RandomUtil.randomSeq(24) in the constructor (fromJson defaults it to "").
			// Minted even with ipsecEnable off, exactly as the form does, so flipping
			// the switch later does not require also inventing a secret.
			gen("ipsecPsk", func() any { return random.Seq(24) }),
			def("allowRaw", true),
			def("fouEnable", false),
			def("fouPort", 15547),
			def("clients", noClients()),
			def("clientToClient", false),
			def("crossInbound", false),
			def("ipRanges", emptyList()),
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
		}

	case model.MTPROTO:
		// Inbound.MtprotoSettings. The proxy's policy is the INBOUND's: telemt applies
		// the FakeTLS domain process-wide, and its mode map has to be spelled out per
		// account or a missing entry reads as "no restriction". The secret, the link
		// endpoints and the ad tag stay per-account, so none of them is seeded here.
		//
		// All three modes on and userLimit 10 (ten devices per account) are the values
		// Inbound.MtprotoSettings' constructor uses, so an inbound created through the
		// API matches one created in the form. 0 stays settable and does NOT mean
		// unlimited: effectiveUserLimit reads it as the bounded 16-device block, which is
		// why it is not the default any more.
		return []settingDefault{
			def("modeClassic", true),
			def("modeSecure", true),
			def("modeTls", true),
			def("tlsDomain", "www.google.com"),
			def("userLimit", 10),
			def("clients", noClients()),
			// The inbound-wide link endpoints, overridden per account by the client's
			// own externalProxy.
			def("externalProxy", emptyList()),
		}

	case model.SSH:
		// Inbound.SshSettings. userLimit 10 = ten concurrent devices, which is what the
		// constructor (and therefore the Add form) uses. fromJson resolves an ABSENT
		// value to 1 instead, matching effectiveSshK(nil) for inbounds stored before the
		// field existed; a caller who omits the key here is creating a NEW inbound, so
		// the constructor's 10 is the right reading. 0 is still settable and SSH is the
		// one protocol where it really does mean no cap at all.
		return []settingDefault{
			def("userLimit", 10),
			def("userLimitStrategy", "accept"),
			def("externalProxy", emptyList()),
			def("clients", noClients()),
			// Minted by SshService on first use and kept stable so a client's host-key
			// pin holds across restarts. Never set from outside.
			def("hostKey", ""),
		}

	case model.ANYTLS:
		// Inbound.AnytlsSettings
		return []settingDefault{
			def("clients", noClients()),
			// Inbound.AnytlsSettings.DEFAULT_PADDING_SCHEME: upstream AnyTLS's own
			// scheme, spelled out rather than left empty so what the server will
			// actually do is visible and editable. The scheme is SERVER-AUTHORITATIVE
			// (handed to the client in the session's settings frame), so changing it
			// never requires reconfiguring a client.
			def("paddingScheme", []string{
				"stop=8",
				"0=30-30",
				"1=100-400",
				"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
				"3=9-9,500-1000",
				"4=500-1000",
				"5=500-1000",
				"6=500-1000",
				"7=500-1000",
			}),
		}

	case model.TUIC:
		// Inbound.TuicSettings
		return []settingDefault{
			def("clients", noClients()),
			def("congestionControl", "cubic"),
			def("authTimeout", 3),
			def("zeroRttHandshake", false),
			def("heartbeat", 10),
			def("udpTimeout", 60),
		}

	case model.NAIVE:
		// Inbound.NaiveSettings. `network` is the SINGLE SOURCE OF TRUTH for which
		// wires the listener owns: NormalizeNaiveInboundStream forces the transport
		// from here onto the stream, OVERRIDING streamSettings.network.
		return []settingDefault{
			def("clients", noClients()),
			def("network", "tcp"),
			// All four keys are kept even though each of file/url/string belongs to
			// exactly one type, which is what lets the form switch type back and forth
			// without losing what was typed under the other one.
			def("masquerade", map[string]any{
				"type":   "404",
				"file":   "",
				"url":    "",
				"string": "",
			}),
		}
	}
	return nil
}

// DefaultSettingsFor returns the settings JSON a freshly created inbound of a protocol
// should carry, matching what the panel's Add form produces minus the one account its
// JS constructor seeds (see noClients).
//
// Errors for a protocol with no server-side shape rather than returning "{}": an empty
// object is a plausible-looking answer that would strip an Xray-native inbound of
// everything the core needs.
func DefaultSettingsFor(protocol model.Protocol) (string, error) {
	defaults := protocolSettingDefaults(protocol)
	if len(defaults) == 0 {
		return "", common.NewErrorf("no server-side settings defaults for protocol %q", protocol)
	}
	root := make(map[string]any, len(defaults))
	for _, d := range defaults {
		root[d.key] = d.value()
	}
	bs, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", common.NewErrorf("building default %s settings: %v", protocol, err)
	}
	return string(bs), nil
}

// FillSettingsDefaults completes whatever the caller posted, adding every key of the
// protocol's shape that is missing and touching nothing that is present.
//
// The no-op case is load-bearing. Every request the panel's own UI makes already
// carries the full shape, and those must keep storing the SAME BYTES they do today, or
// this turns into a rewrite of every inbound anyone saves. So when no key was missing
// the input string is returned verbatim rather than re-marshalled: re-encoding would
// reorder keys and renumber floats even though nothing changed.
//
// Values already present are copied as raw JSON, never decoded and re-encoded, so a
// large integer (an expiryTime in milliseconds, a totalGB in bytes) cannot lose
// precision on the way through.
//
// A protocol with no server-side shape is passed through untouched.
func FillSettingsDefaults(protocol model.Protocol, posted string) (string, error) {
	defaults := protocolSettingDefaults(protocol)
	if len(defaults) == 0 {
		return posted, nil
	}
	root, err := settingsRaw(posted)
	if err != nil {
		return "", err
	}
	added := false
	for _, d := range defaults {
		if _, ok := root[d.key]; ok {
			continue
		}
		bs, err := json.Marshal(d.value())
		if err != nil {
			return "", common.NewErrorf("building the default for %q: %v", d.key, err)
		}
		root[d.key] = bs
		added = true
	}
	if !added {
		return posted, nil
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", common.NewErrorf("filling %s settings defaults: %v", protocol, err)
	}
	return string(out), nil
}

// settingsRaw parses a settings blob into its top-level keys, keeping each value as the
// exact bytes the caller sent.
//
// An empty blob (and a literal null, which is what an absent field marshals to) is an
// empty object rather than an error: creating an inbound with no settings at all is the
// minimal API body this whole file exists to support.
func settingsRaw(settings string) (map[string]json.RawMessage, error) {
	trimmed := strings.TrimSpace(settings)
	if trimmed == "" || trimmed == "null" {
		return map[string]json.RawMessage{}, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &root); err != nil {
		return nil, common.NewErrorf("inbound settings must be a JSON object: %v", err)
	}
	if root == nil {
		return map[string]json.RawMessage{}, nil
	}
	return root, nil
}

// NormalizeInboundSettings fills a new inbound's missing settings keys and then
// validates the result. The ADD path's single entry point into this file.
//
// Order matters: validation runs on the FILLED blob, so a caller who omitted a field is
// judged on the default that will actually be stored, not on its absence.
func NormalizeInboundSettings(inbound *model.Inbound) error {
	if inbound == nil {
		return nil
	}
	// MTProto only, and BEFORE the defaults on purpose: a body written against the old
	// field names carries its connection modes, FakeTLS domain and device cap on its
	// CLIENTS, and filling the inbound-level defaults over that would both lose them and
	// make the blob look already-migrated to the startup lift. See
	// liftMtprotoSettingsBlob. A no-op for every other protocol and for a body already
	// in the current shape, which is every body the panel's own form sends.
	inbound.Settings = liftMtprotoSettingsBlob(inbound.Protocol, inbound.Settings)

	filled, err := FillSettingsDefaults(inbound.Protocol, inbound.Settings)
	if err != nil {
		return err
	}
	inbound.Settings = filled
	return ValidateProtocolSettings(inbound.Protocol, inbound.Settings)
}
