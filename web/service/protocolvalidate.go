package service

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strings"

	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/util/common"
)

// Per-protocol validation of an inbound's settings JSON, the second half of what
// protocoldefaults.go exists for: once the server fills a caller's missing keys, it has
// to be able to say what is wrong with the keys the caller did send.
//
// Two rules decide what is checked here, and nothing else is:
//
//  1. Anything the protocol's OWN Go struct cannot unmarshal. l2tpSettings.Mtu is an
//     int, so a `"mtu": ""` (which is what Vue's v-model.number leaves behind when the
//     operator clears the box) makes the whole json.Unmarshal fail inside the daemon
//     config writer. Nothing surfaces that: the inbound saves, the daemon comes up on
//     zero values or not at all, and the panel shows a healthy row.
//
//  2. Values that parse but cannot work: a port outside 1-65535, an ipRanges entry that
//     is not a CIDR, an enum the protocol will silently fall back from. The strategy
//     resolvers absorb an unknown value rather than complain (normUserLimitStrategy
//     turns anything that is not "reject" into "accept"), so a typo like "Accept" or
//     "evict" is accepted and then discarded, which is precisely the class of mistake
//     an API caller writing the blob by hand makes.
//
// Everything else is left alone. A check that rejects a blob the panel's own form can
// produce is a regression, not a safety net: this runs on the UI's requests too.

// ValidateProtocolSettings checks one inbound's settings JSON against its protocol's
// shape. A protocol with no server-side shape (every Xray-native one) validates clean:
// the core owns those blobs and rejects what it cannot use itself.
func ValidateProtocolSettings(protocol model.Protocol, settings string) error {
	validate := protocolSettingValidators[protocol]
	if validate == nil {
		return nil
	}
	root, err := settingsObject(settings)
	if err != nil {
		return err
	}
	if err := checkClients(root); err != nil {
		return err
	}
	return validate(root)
}

// protocolSettingValidators is keyed by protocol so a protocol without an entry is
// unmistakably "not validated here" rather than "fell through a switch".
var protocolSettingValidators = map[model.Protocol]func(map[string]any) error{
	model.L2TP:        validateL2tpSettings,
	model.PPTP:        validatePptpSettings,
	model.OPENVPN:     validateOpenvpnSettings,
	model.OPENCONNECT: validateOcservSettings,
	model.SSTP:        validateSstpSettings,
	model.IKEV2:       validateIkev2Settings,
	model.WGC:         validateWgcSettings,
	model.AWG:         validateAwgSettings,
	model.GRE:         validateGreSettings,
	model.MTPROTO:     validateMtprotoSettings,
	model.SSH:         validateSshSettings,
	model.ANYTLS:      validateAnytlsSettings,
	model.TUIC:        validateTuicSettings,
	model.NAIVE:       validateNaiveSettings,
}

// --- per-protocol validators -------------------------------------------------------

func validateL2tpSettings(m map[string]any) error {
	if err := checkAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"ipsecEnable", "allowRaw", "clientToClient", "crossInbound"} {
		if _, _, err := optBool(m, key); err != nil {
			return err
		}
	}
	// A shared secret is the whole of L2TP/IPsec's authentication of the tunnel. With
	// the mode on and the secret empty, libreswan gets a conn with no PSK and every
	// client fails at phase 1 with an error the panel never sees.
	ipsec, _, err := optBool(m, "ipsecEnable")
	if err != nil {
		return err
	}
	psk, _, err := optString(m, "ipsecPsk")
	if err != nil {
		return err
	}
	if ipsec && strings.TrimSpace(psk) == "" {
		return common.NewError(`"ipsecPsk" is required when "ipsecEnable" is true`)
	}
	return checkExternalProxy(m)
}

func validatePptpSettings(m map[string]any) error {
	if err := checkAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"clientToClient", "crossInbound"} {
		if _, _, err := optBool(m, key); err != nil {
			return err
		}
	}
	return checkExternalProxy(m)
}

func validateOpenvpnSettings(m map[string]any) error {
	if err := checkAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"udpEnable", "tcpEnable", "separatePorts", "tlsUseFile", "clientToClient", "crossInbound"} {
		if _, _, err := optBool(m, key); err != nil {
			return err
		}
	}
	if err := checkOptionalPort(m, "tcpPort"); err != nil {
		return err
	}
	if err := checkEnum(m, "cipherMode", "old", "new", "all", "custom"); err != nil {
		return err
	}
	// The list order IS the `data-ciphers` preference order, and an empty one leaves the
	// directive with no algorithms: openvpn then refuses every negotiation rather than
	// falling back to a default.
	ciphers, present, err := optStrings(m, "ciphers")
	if err != nil {
		return err
	}
	if present && len(ciphers) == 0 {
		return common.NewError(`"ciphers" must list at least one cipher`)
	}
	for _, key := range []string{"caCert", "caKey", "serverCert", "serverKey", "tlsCrypt", "caCertFile", "serverCertFile", "serverKeyFile", "tlsCryptFile"} {
		if _, _, err := optString(m, key); err != nil {
			return err
		}
	}
	return checkExternalProxy(m)
}

func validateOcservSettings(m map[string]any) error {
	return validateTlsPppFamily(m)
}

func validateSstpSettings(m map[string]any) error {
	return validateTlsPppFamily(m)
}

// validateTlsPppFamily covers the two protocols whose settings shape is identical
// (OpenConnect and SSTP): DNS/MTU/pool plus the Xray-style TLS cert pair.
func validateTlsPppFamily(m map[string]any) error {
	if err := checkAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"tlsUseFile", "clientToClient", "crossInbound"} {
		if _, _, err := optBool(m, key); err != nil {
			return err
		}
	}
	if err := checkTlsCertFields(m); err != nil {
		return err
	}
	return checkExternalProxy(m)
}

func validateIkev2Settings(m map[string]any) error {
	if err := checkAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"tlsUseFile", "clientToClient", "crossInbound"} {
		if _, _, err := optBool(m, key); err != nil {
			return err
		}
	}
	if err := checkTlsCertFields(m); err != nil {
		return err
	}
	if err := checkOptionalPort(m, "nattPort"); err != nil {
		return err
	}
	if err := checkEnum(m, "authMode", "eap-mschapv2", "psk", "eap-tls"); err != nil {
		return err
	}
	if _, _, err := optString(m, "serverAddr"); err != nil {
		return err
	}
	// PSK mode has no per-account credential at all: the shared secret IS the
	// authentication, so an empty one is an inbound anybody can attach to.
	mode, _, err := optString(m, "authMode")
	if err != nil {
		return err
	}
	psk, _, err := optString(m, "psk")
	if err != nil {
		return err
	}
	if strings.TrimSpace(mode) == "psk" && strings.TrimSpace(psk) == "" {
		return common.NewError(`"psk" is required when "authMode" is "psk"`)
	}
	return checkExternalProxy(m)
}

func validateWgcSettings(m map[string]any) error {
	return validateWireguardFamily(m)
}

func validateAwgSettings(m map[string]any) error {
	if err := validateWireguardFamily(m); err != nil {
		return err
	}
	// AWG 1.0 obfuscation. Jc is a packet COUNT and Jmin/Jmax a byte range, so
	// Jmin > Jmax is not a preference, it is a range the generator cannot satisfy.
	for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2"} {
		v, present, err := optInt(m, key)
		if err != nil {
			return err
		}
		if present && v < 0 {
			return common.NewErrorf("%q must not be negative (got %d)", key, v)
		}
	}
	jmin, hasMin, err := optInt(m, "jmin")
	if err != nil {
		return err
	}
	jmax, hasMax, err := optInt(m, "jmax")
	if err != nil {
		return err
	}
	if hasMin && hasMax && jmin > jmax {
		return common.NewErrorf(`"jmin" (%d) must not exceed "jmax" (%d)`, jmin, jmax)
	}
	for _, key := range []string{"h1", "h2", "h3", "h4"} {
		if _, _, err := optString(m, key); err != nil {
			return err
		}
	}
	return nil
}

// validateWireguardFamily covers wg-c and awg, whose shapes differ only by the AWG
// obfuscation block validated above.
func validateWireguardFamily(m map[string]any) error {
	if err := checkAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"pskEnable", "clientToClient", "crossInbound"} {
		if _, _, err := optBool(m, key); err != nil {
			return err
		}
	}
	for _, key := range []string{"serverPrivKey", "serverPubKey"} {
		if _, _, err := optString(m, key); err != nil {
			return err
		}
	}
	return checkExternalProxy(m)
}

func validateGreSettings(m map[string]any) error {
	if err := checkAddressedVpnCommon(m); err != nil {
		return err
	}
	for _, key := range []string{"ipsecEnable", "allowRaw", "fouEnable", "clientToClient", "crossInbound"} {
		if _, _, err := optBool(m, key); err != nil {
			return err
		}
	}
	// GRE carries no credential of its own, so with IPsec on the PSK is the only thing
	// separating a customer's tunnel from anybody who knows the address.
	ipsec, _, err := optBool(m, "ipsecEnable")
	if err != nil {
		return err
	}
	psk, _, err := optString(m, "ipsecPsk")
	if err != nil {
		return err
	}
	if ipsec && strings.TrimSpace(psk) == "" {
		return common.NewError(`"ipsecPsk" is required when "ipsecEnable" is true`)
	}
	ttl, present, err := optInt(m, "ttl")
	if err != nil {
		return err
	}
	// 0 leaves it to the kernel; the field is one octet on the wire past that.
	if present && (ttl < 0 || ttl > 255) {
		return common.NewErrorf(`"ttl" must be 0 (kernel default) or 1-255 (got %d)`, ttl)
	}
	if err := checkOptionalPort(m, "fouPort"); err != nil {
		return err
	}
	// FOU is a UDP encapsulation, so with it on the port is not optional: without one
	// there is nothing for the peer's fou tunnel to send to.
	fou, _, err := optBool(m, "fouEnable")
	if err != nil {
		return err
	}
	fouPort, _, err := optInt(m, "fouPort")
	if err != nil {
		return err
	}
	if fou && fouPort == 0 {
		return common.NewError(`"fouPort" is required when "fouEnable" is true`)
	}
	return nil
}

func validateMtprotoSettings(m map[string]any) error {
	// The inbound owns nothing but its port and its account list; everything else is
	// per-account (see Inbound.MtprotoSettings), so there is nothing else to check.
	return nil
}

func validateSshSettings(m map[string]any) error {
	if err := checkUserLimit(m); err != nil {
		return err
	}
	if err := checkUserLimitStrategy(m); err != nil {
		return err
	}
	if _, _, err := optString(m, "hostKey"); err != nil {
		return err
	}
	return checkExternalProxy(m)
}

func validateAnytlsSettings(m map[string]any) error {
	// The scheme's own grammar is the core's to police (it is handed to the client
	// verbatim in the settings frame); the shape is ours.
	if _, _, err := optStrings(m, "paddingScheme"); err != nil {
		return err
	}
	return nil
}

func validateTuicSettings(m map[string]any) error {
	if err := checkEnum(m, "congestionControl", "cubic", "bbr", "new_reno"); err != nil {
		return err
	}
	if _, _, err := optBool(m, "zeroRttHandshake"); err != nil {
		return err
	}
	// All three are seconds and all three read 0 as "use the built-in default"
	// (see infra/conf/tuic.go), so only a negative value is meaningless.
	for _, key := range []string{"authTimeout", "heartbeat", "udpTimeout"} {
		v, present, err := optInt(m, key)
		if err != nil {
			return err
		}
		if present && v < 0 {
			return common.NewErrorf("%q must not be negative (got %d)", key, v)
		}
	}
	return nil
}

func validateNaiveSettings(m map[string]any) error {
	// ParseNetwork reads an unrecognised spelling as "both wires" rather than failing,
	// so a typo here does not error, it silently opens a listener the operator did not
	// ask for. Accept every spelling the core understands and nothing else.
	network, present, err := optString(m, "network")
	if err != nil {
		return err
	}
	if present && strings.TrimSpace(network) != "" {
		for _, part := range strings.Split(strings.ToLower(network), ",") {
			switch strings.TrimSpace(part) {
			case "tcp", "h2", "http2", "udp", "h3", "http3", "quic":
			default:
				return common.NewErrorf(`"network" has an unknown transport %q (expected "tcp", "udp" or "tcp,udp")`, strings.TrimSpace(part))
			}
		}
	}

	raw, ok := m["masquerade"]
	if !ok || raw == nil {
		return nil
	}
	masq, ok := raw.(map[string]any)
	if !ok {
		return common.NewError(`"masquerade" must be an object`)
	}
	if err := checkEnum(masq, "type", "404", "file", "proxy", "string"); err != nil {
		return common.NewErrorf("masquerade: %v", err)
	}
	typ, _, err := optString(masq, "type")
	if err != nil {
		return common.NewErrorf("masquerade: %v", err)
	}
	for _, key := range []string{"file", "url", "string"} {
		if _, _, err := optString(masq, key); err != nil {
			return common.NewErrorf("masquerade: %v", err)
		}
	}
	// Each type reads exactly one of the three companion fields, and an empty one is
	// not a degraded masquerade, it is a listener the core refuses to build (a "file"
	// with no directory, a "proxy" with no upstream) or one that serves nothing.
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "file":
		if v, _, _ := optString(masq, "file"); strings.TrimSpace(v) == "" {
			return common.NewError(`"masquerade.file" is required when "masquerade.type" is "file"`)
		}
	case "proxy":
		if v, _, _ := optString(masq, "url"); strings.TrimSpace(v) == "" {
			return common.NewError(`"masquerade.url" is required when "masquerade.type" is "proxy"`)
		}
	case "string":
		if v, _, _ := optString(masq, "string"); strings.TrimSpace(v) == "" {
			return common.NewError(`"masquerade.string" is required when "masquerade.type" is "string"`)
		}
	}
	return nil
}

// --- shared checks -----------------------------------------------------------------

// checkAddressedVpnCommon validates the block every protocol that hands out a tunnel
// address shares: the two resolvers, the MTU, the address pool and the device cap.
func checkAddressedVpnCommon(m map[string]any) error {
	if err := checkDNS(m, "dns1"); err != nil {
		return err
	}
	if err := checkDNS(m, "dns2"); err != nil {
		return err
	}
	if err := checkMTU(m); err != nil {
		return err
	}
	if err := checkIPRanges(m); err != nil {
		return err
	}
	if err := checkUserLimit(m); err != nil {
		return err
	}
	return checkUserLimitStrategy(m)
}

// checkTlsCertFields type-checks the Xray-style cert pair shared by ocserv, sstp and
// ikev2. Whether a cert is REQUIRED is validateInboundConfig's call (it differs per
// protocol and per auth mode); this only refuses a value of the wrong type, which would
// otherwise break the daemon's own unmarshal of the same blob.
func checkTlsCertFields(m map[string]any) error {
	for _, key := range []string{"certificateFile", "keyFile", "certificate", "key", "caCert"} {
		if _, _, err := optString(m, key); err != nil {
			return err
		}
	}
	return nil
}

// checkDNS accepts an empty value (the daemon falls back to its own default) and any
// literal IP. A hostname is refused: these are written verbatim into a PPP/WireGuard
// client config as a nameserver address, where a name has nothing to resolve it.
func checkDNS(m map[string]any, key string) error {
	v, present, err := optString(m, key)
	if err != nil {
		return err
	}
	v = strings.TrimSpace(v)
	if !present || v == "" {
		return nil
	}
	if _, err := netip.ParseAddr(v); err != nil {
		return common.NewErrorf("%q must be an IP address (got %q)", key, v)
	}
	return nil
}

// checkMTU allows 0, which every protocol here reads as "leave it to the daemon or the
// kernel" (see awgSettings.mtu, greSettings). Past that the floor is IPv4's minimum
// reassembly buffer and the ceiling is a jumbo frame.
func checkMTU(m map[string]any) error {
	mtu, present, err := optInt(m, "mtu")
	if err != nil {
		return err
	}
	if !present || mtu == 0 {
		return nil
	}
	if mtu < 576 || mtu > 9216 {
		return common.NewErrorf(`"mtu" must be 0 (protocol default) or 576-9216 (got %d)`, mtu)
	}
	return nil
}

// checkIPRanges refuses an address pool entry the allocator cannot read. These are NOT
// CIDRs: the format is the inclusive "A.B.C.s-A.B.C.e" host range (with an "A.B.C.s-e"
// last-octet shorthand) that vpnrange.go's parseRange accepts, both ends inside one /24
// and non-decreasing. parseRange silently DROPS anything else, so a caller who writes
// the pool as "10.4.0.0/24" gets an inbound with no addresses and no complaint.
func checkIPRanges(m map[string]any) error {
	ranges, present, err := optStrings(m, "ipRanges")
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		// An empty row is what the form leaves behind between edits and the JS filters
		// it out on save, so it means "unset", not "broken".
		if r == "" {
			continue
		}
		if _, _, ok := parseRange(r); !ok {
			return common.NewErrorf(`"ipRanges" entry %q is not an address range (want e.g. "10.1.0.2-10.1.0.254", both ends in one /24)`, r)
		}
	}
	return nil
}

// checkUserLimit bounds the per-account device cap. 0 is legal and means "no limit"
// (which the allocator sizes as noLimitDevices), so only a negative or an over-cap
// value is wrong. normUserLimit would clamp both silently.
func checkUserLimit(m map[string]any) error {
	k, present, err := optInt(m, "userLimit")
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	if k < 0 || k > maxUserLimit {
		return common.NewErrorf(`"userLimit" must be 0 (no limit) or 1-%d (got %d)`, maxUserLimit, k)
	}
	return nil
}

// checkUserLimitStrategy mirrors the IPLimitStrategy guard in validateInboundConfig:
// normUserLimitStrategy absorbs anything that is not "reject" as "accept", so a typo is
// accepted at save time and then quietly discarded.
func checkUserLimitStrategy(m map[string]any) error {
	return checkEnum(m, "userLimitStrategy", "accept", "reject")
}

// checkClients refuses a clients value that is not an array. GetClients unmarshals the
// whole settings object into map[string][]model.Client and IGNORES the error, so an
// object here yields no clients and no complaint: an inbound that listens and can
// authenticate nobody.
func checkClients(m map[string]any) error {
	v, ok := m["clients"]
	if !ok || v == nil {
		return nil
	}
	if _, ok := v.([]any); !ok {
		return common.NewError(`"clients" must be an array`)
	}
	return nil
}

// checkExternalProxy validates the advertised-endpoint override list. It never reaches
// a daemon (it only rewrites the address in generated links and configs), so the bar is
// only that each entry is an object whose port is a port.
func checkExternalProxy(m map[string]any) error {
	v, ok := m["externalProxy"]
	if !ok || v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return common.NewError(`"externalProxy" must be an array`)
	}
	for i, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			return common.NewErrorf(`"externalProxy" entry %d must be an object with "dest" and "port"`, i)
		}
		if _, _, err := optString(entry, "dest"); err != nil {
			return common.NewErrorf(`"externalProxy" entry %d: %v`, i, err)
		}
		port, present, err := optInt(entry, "port")
		if err != nil {
			return common.NewErrorf(`"externalProxy" entry %d: %v`, i, err)
		}
		if present && (port < 0 || port > 65535) {
			return common.NewErrorf(`"externalProxy" entry %d has port %d outside 1-65535`, i, port)
		}
	}
	return nil
}

// checkOptionalPort bounds a port field that may legitimately be 0 (unset, because the
// feature owning it is off). Whether it is REQUIRED is the caller's rule.
func checkOptionalPort(m map[string]any, key string) error {
	port, present, err := optInt(m, key)
	if err != nil {
		return err
	}
	if !present || port == 0 {
		return nil
	}
	if port < 1 || port > 65535 {
		return common.NewErrorf("%q must be 1-65535 (got %d)", key, port)
	}
	return nil
}

// checkEnum accepts an absent or empty value (every one of these fields has a
// server-side default for exactly that case) and rejects anything outside the set.
func checkEnum(m map[string]any, key string, allowed ...string) error {
	v, present, err := optString(m, key)
	if err != nil {
		return err
	}
	v = strings.TrimSpace(v)
	if !present || v == "" {
		return nil
	}
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return common.NewErrorf("%q must be one of %s (got %q)", key, quotedList(allowed), v)
}

func quotedList(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, fmt.Sprintf("%q", v))
	}
	return strings.Join(quoted, ", ")
}

// --- typed accessors ---------------------------------------------------------------
//
// All four report "present" separately from the value, because an ABSENT field and a
// zero one are different answers everywhere in this package (a nil *int userLimit is a
// legacy single-device inbound, an explicit 0 is no limit).

// settingsObject decodes a settings blob for reading. Values keep JSON's own types, so
// numbers arrive as float64 and optInt below is what turns them back into integers.
func settingsObject(settings string) (map[string]any, error) {
	trimmed := strings.TrimSpace(settings)
	if trimmed == "" || trimmed == "null" {
		return map[string]any{}, nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(trimmed), &root); err != nil {
		return nil, common.NewErrorf("inbound settings must be a JSON object: %v", err)
	}
	if root == nil {
		return map[string]any{}, nil
	}
	return root, nil
}

func optString(m map[string]any, key string) (string, bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", false, common.NewErrorf("%q must be a string", key)
	}
	return s, true, nil
}

// optInt refuses a numeric-looking STRING as hard as it refuses a word. The protocols'
// own settings structs type these as int, so `"mtu": "1400"` fails their json.Unmarshal
// just as `"mtu": ""` does, and the daemon config writer that hits it has nowhere to
// report from. Vue's v-model.number leaves the raw string behind whenever the box is
// cleared or holds something unparseable, so this is a real shape, not a hypothetical.
func optInt(m map[string]any, key string) (int, bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return 0, false, nil
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false, common.NewErrorf("%q must be a number", key)
	}
	if f != math.Trunc(f) {
		return 0, false, common.NewErrorf("%q must be a whole number (got %v)", key, f)
	}
	return int(f), true, nil
}

func optBool(m map[string]any, key string) (bool, bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return false, false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, false, common.NewErrorf("%q must be true or false", key)
	}
	return b, true, nil
}

func optStrings(m map[string]any, key string) ([]string, bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, false, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false, common.NewErrorf("%q must be an array of strings", key)
	}
	out := make([]string, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, false, common.NewErrorf("%q entry %d must be a string", key, i)
		}
		out = append(out, s)
	}
	return out, true, nil
}
