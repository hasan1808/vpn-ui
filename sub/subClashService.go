package sub

import (
	"fmt"
	"strings"

	"github.com/goccy/go-json"
	yaml "github.com/goccy/go-yaml"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

type SubClashService struct {
	inboundService service.InboundService
	wgcService     service.WgcService
	awgService     service.AwgService
	SubService     *SubService
}

type ClashConfig struct {
	Proxies     []map[string]any `yaml:"proxies"`
	ProxyGroups []map[string]any `yaml:"proxy-groups"`
	Rules       []string         `yaml:"rules"`
}

func NewSubClashService(subService *SubService) *SubClashService {
	return &SubClashService{SubService: subService}
}

// forResponse mirrors SubService.forResponse: one SubClashService is built at
// start-up and shared across requests, so the per-response scope lives on a copy.
// It matters more here than anywhere else, because Clash proxies are keyed by name
// and a duplicate name is not a second server, it is a replacement.
// Its own service fields are rebuilt as zero values for the same reason as in
// SubService.forResponse: nothing assigns them, and two of them carry a mutex.
func (s *SubClashService) forResponse() *SubClashService {
	return &SubClashService{SubService: s.SubService.forResponse()}
}

func (s *SubClashService) GetClash(subId string, host string) (string, string, error) {
	s = s.forResponse()
	inbounds, err := s.SubService.getInboundsBySubId(subId)
	if err != nil || len(inbounds) == 0 {
		return "", "", err
	}

	usage := newSubUsage()
	var proxies []map[string]any

	for _, inbound := range inbounds {
		clients, err := s.inboundService.GetClients(inbound)
		if err != nil {
			logger.Error("SubClashService - GetClients: Unable to get clients from inbound")
		}
		if clients == nil {
			continue
		}
		if len(inbound.Listen) > 0 && inbound.Listen[0] == '@' {
			listen, port, streamSettings, err := s.SubService.getFallbackMaster(inbound.Listen, inbound.StreamSettings)
			if err == nil {
				inbound.Listen = listen
				inbound.Port = port
				inbound.StreamSettings = streamSettings
			}
		}
		for _, client := range clients {
			if client.Enable && client.SubID == subId {
				ct, accountBacked, _ := s.SubService.resolveTraffic(inbound, client.Email)
				usage.add(client.Email, ct, accountBacked)
				proxies = append(proxies, s.getProxies(inbound, client, host)...)
			}
		}
	}

	if len(proxies) == 0 {
		return "", "", nil
	}

	// Folded per identity: see subUsage. Summing the per-inbound rows reported an
	// account served on several inbounds as unlimited and never expiring.
	traffic := usage.result()

	proxyNames := make([]string, 0, len(proxies)+1)
	for _, proxy := range proxies {
		if name, ok := proxy["name"].(string); ok && name != "" {
			proxyNames = append(proxyNames, name)
		}
	}
	proxyNames = append(proxyNames, "DIRECT")

	config := ClashConfig{
		Proxies: proxies,
		ProxyGroups: []map[string]any{{
			"name":    "PROXY",
			"type":    "select",
			"proxies": proxyNames,
		}},
		Rules: []string{"MATCH,PROXY"},
	}

	finalYAML, err := yaml.Marshal(config)
	if err != nil {
		return "", "", err
	}

	header := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
	return string(finalYAML), header, nil
}

func (s *SubClashService) getProxies(inbound *model.Inbound, client model.Client, host string) []map[string]any {
	// wg-c/awg carry key material and emit one proxy per device x endpoint, not the
	// stream/externalProxy shape the rest of the protocols use.
	switch inbound.Protocol {
	case model.WGC:
		return s.buildWireguardProxies(inbound, client, host, false)
	case model.AWG:
		return s.buildWireguardProxies(inbound, client, host, true)
	}
	stream := s.streamData(inbound.StreamSettings)
	externalProxies, ok := stream["externalProxy"].([]any)
	if !ok || len(externalProxies) == 0 {
		externalProxies = []any{map[string]any{
			"forceTls": "same",
			"dest":     host,
			"port":     float64(inbound.Port),
			"remark":   "",
		}}
	}
	delete(stream, "externalProxy")

	proxies := make([]map[string]any, 0, len(externalProxies))
	for _, ep := range externalProxies {
		extPrxy := ep.(map[string]any)
		workingInbound := *inbound
		workingInbound.Listen = extPrxy["dest"].(string)
		workingInbound.Port = int(extPrxy["port"].(float64))
		workingStream := cloneMap(stream)

		switch extPrxy["forceTls"].(string) {
		case "tls":
			if workingStream["security"] != "tls" {
				workingStream["security"] = "tls"
				workingStream["tlsSettings"] = map[string]any{}
			}
		case "none":
			if workingStream["security"] != "none" {
				workingStream["security"] = "none"
				delete(workingStream, "tlsSettings")
				delete(workingStream, "realitySettings")
			}
		}

		proxy := s.buildProxy(&workingInbound, client, workingStream, extPrxy["remark"].(string))
		if len(proxy) > 0 {
			proxies = append(proxies, proxy)
		}
	}
	return proxies
}

// buildWireguardProxies emits Clash `type: wireguard` proxies for a wg-c or awg client,
// one per device x endpoint, from the protocol service's structured params (the key
// material the stream-based builders do not carry). awg additionally emits mihomo's
// `amnezia-wg-option` obfuscation block.
//
// NOTE: mihomo's wireguard field names have drifted across versions; verify the awg
// output against the target client. wg-c uses only the stable, documented fields.
func (s *SubClashService) buildWireguardProxies(inbound *model.Inbound, client model.Client, host string, awg bool) []map[string]any {
	base := func(p service.WgcClientParams) map[string]any {
		proxy := map[string]any{
			"name":        s.SubService.genRemark(inbound, client.Email, p.Name),
			"type":        "wireguard",
			"server":      p.Host,
			"port":        p.Port,
			"udp":         true,
			"ip":          strings.TrimSuffix(p.Address, "/32"),
			"private-key": p.PrivateKey,
			"public-key":  p.PublicKey,
		}
		if p.PreSharedKey != "" {
			proxy["pre-shared-key"] = p.PreSharedKey
		}
		if p.MTU > 0 {
			proxy["mtu"] = p.MTU
		}
		if len(p.DNS) > 0 {
			proxy["dns"] = p.DNS
		}
		if len(p.AllowedIPs) > 0 {
			proxy["allowed-ips"] = p.AllowedIPs
		}
		return proxy
	}

	if awg {
		params, err := s.awgService.RenderClientParams(inbound, client.Email, host)
		if err != nil {
			logger.Error("SubClashService - awg RenderClientParams:", err)
			return nil
		}
		proxies := make([]map[string]any, 0, len(params))
		for _, p := range params {
			proxy := base(p.WgcClientParams)
			proxy["amnezia-wg-option"] = map[string]any{
				"jc": p.Jc, "jmin": p.Jmin, "jmax": p.Jmax,
				"s1": p.S1, "s2": p.S2,
				"h1": p.H1, "h2": p.H2, "h3": p.H3, "h4": p.H4,
			}
			proxies = append(proxies, proxy)
		}
		return proxies
	}

	params, err := s.wgcService.RenderClientParams(inbound, client.Email, host)
	if err != nil {
		logger.Error("SubClashService - wgc RenderClientParams:", err)
		return nil
	}
	proxies := make([]map[string]any, 0, len(params))
	for _, p := range params {
		proxies = append(proxies, base(p))
	}
	return proxies
}

func (s *SubClashService) buildProxy(inbound *model.Inbound, client model.Client, stream map[string]any, extraRemark string) map[string]any {
	// Hysteria has its own transport + TLS model, applyTransport /
	// applySecurity don't fit. IsHysteria also covers the literal
	// "hysteria2" protocol string (#4081).
	if model.IsHysteria(inbound.Protocol) {
		return s.buildHysteriaProxy(inbound, client, extraRemark)
	}
	// Same story for anytls and tuic: mihomo declares a fixed set of keys per proxy
	// type and neither fits the network/tls shape below. naive is deliberately absent:
	// mihomo has no naive proxy type at all, so it falls through to the switch's
	// `default: return nil` and gets no Clash entry. Those accounts are delivered by
	// the raw sub's naive+https:// link instead.
	switch inbound.Protocol {
	case model.ANYTLS:
		return s.buildAnytlsProxy(inbound, client, extraRemark)
	case model.TUIC:
		return s.buildTuicProxy(inbound, client, extraRemark)
	}

	proxy := map[string]any{
		"name":   s.SubService.genRemark(inbound, client.Email, extraRemark),
		"server": inbound.Listen,
		"port":   inbound.Port,
		"udp":    true,
	}

	network, _ := stream["network"].(string)
	if !s.applyTransport(proxy, network, stream) {
		return nil
	}

	switch inbound.Protocol {
	case model.VMESS:
		proxy["type"] = "vmess"
		proxy["uuid"] = client.ID
		proxy["alterId"] = 0
		cipher := client.Security
		if cipher == "" {
			cipher = "auto"
		}
		proxy["cipher"] = cipher
	case model.VLESS:
		proxy["type"] = "vless"
		proxy["uuid"] = client.ID
		if client.Flow != "" && network == "tcp" {
			proxy["flow"] = client.Flow
		}
		var inboundSettings map[string]any
		json.Unmarshal([]byte(inbound.Settings), &inboundSettings)
		if encryption, ok := inboundSettings["encryption"].(string); ok && encryption != "" {
			proxy["packet-encoding"] = encryption
		}
	case model.Trojan:
		proxy["type"] = "trojan"
		proxy["password"] = client.Password
	case model.Shadowsocks:
		proxy["type"] = "ss"
		proxy["password"] = client.Password
		var inboundSettings map[string]any
		json.Unmarshal([]byte(inbound.Settings), &inboundSettings)
		method, _ := inboundSettings["method"].(string)
		if method == "" {
			return nil
		}
		proxy["cipher"] = method
		if strings.HasPrefix(method, "2022") {
			if serverPassword, ok := inboundSettings["password"].(string); ok && serverPassword != "" {
				proxy["password"] = fmt.Sprintf("%s:%s", serverPassword, client.Password)
			}
		}
	default:
		return nil
	}

	security, _ := stream["security"].(string)
	if !s.applySecurity(proxy, security, stream) {
		return nil
	}

	return proxy
}

// buildHysteriaProxy produces a mihomo-compatible Clash entry for a
// Hysteria (v1) or Hysteria2 inbound. It reads `inbound.StreamSettings`
// directly instead of going through streamData/tlsData, because those
// helpers prune fields (like `allowInsecure` / the salamander obfs
// block) that the hysteria proxy wants preserved.
func (s *SubClashService) buildHysteriaProxy(inbound *model.Inbound, client model.Client, extraRemark string) map[string]any {
	var inboundSettings map[string]any
	_ = json.Unmarshal([]byte(inbound.Settings), &inboundSettings)

	proxyType := "hysteria2"
	authKey := "password"
	if v, ok := inboundSettings["version"].(float64); ok && int(v) == 1 {
		proxyType = "hysteria"
		authKey = "auth-str"
	}

	proxy := map[string]any{
		"name":   s.SubService.genRemark(inbound, client.Email, extraRemark),
		"type":   proxyType,
		"server": inbound.Listen,
		"port":   inbound.Port,
		"udp":    true,
		authKey:  client.Auth,
	}

	var rawStream map[string]any
	_ = json.Unmarshal([]byte(inbound.StreamSettings), &rawStream)

	// TLS details — hysteria always uses TLS.
	applyAlwaysOnTLS(proxy, rawStream)

	// Salamander obfs (Hysteria2). Read the same finalmask.udp[salamander]
	// block the subscription link generator uses.
	if finalmask, ok := rawStream["finalmask"].(map[string]any); ok {
		if udpMasks, ok := finalmask["udp"].([]any); ok {
			for _, m := range udpMasks {
				mask, _ := m.(map[string]any)
				if mask == nil || mask["type"] != "salamander" {
					continue
				}
				settings, _ := mask["settings"].(map[string]any)
				if pw, ok := settings["password"].(string); ok && pw != "" {
					proxy["obfs"] = "salamander"
					proxy["obfs-password"] = pw
					break
				}
			}
		}
	}

	return proxy
}

// buildAnytlsProxy produces a mihomo Clash entry for an AnyTLS inbound.
//
// It bypasses applyTransport/applySecurity because mihomo's anytls proxy is raw TCP
// plus TLS and nothing else: it declares neither `network` nor `tls`, and mihomo errors
// on a proxy carrying keys its type does not know.
//
// Be aware how narrow that makes this. Exactly ONE anytls stream configuration, plain
// tcp + tls, survives; every other one returns nil and the account vanishes from the
// Clash sub. Counting them, because the two obvious counts are both wrong: the transport
// picker (form/stream/stream_settings.html) renders tcp/ws/grpc/httpupgrade/xhttp for
// anytls, and REALITY is offered on only tcp/grpc/xhttp of those, so an operator can
// reach 3*3 + 2*2 = 13 combinations. The MODEL reaches 16, because canEnableTls() also
// accepts "http", which no longer has a select option. Either way, one gets a node.
//
// The drops are deliberate and each is a real mihomo limitation, not an omission: a
// non-tcp transport is inexpressible (mihomo's anytls declares no `network`), REALITY is
// refused outright (the maintainers have said they will not add it), and security=none
// would have mihomo handshake TLS against a plaintext listener. An entry that lied about
// any of those would fail in the handshake instead, which is worse than an absent node.
//
// Those accounts still reach the subscriber through the raw sub's anytls:// link, which
// describes them faithfully.
//
// KNOWN BLIND SPOT, deferred on purpose: this reads inbound.StreamSettings, so it judges
// the INBOUND's own security and not the ENDPOINT's. getProxies has already resolved each
// External Proxy entry's forceTls into the `stream` argument, which this ignores. Two
// consequences, in opposite directions:
//
//   - A TLS-offload inbound (nginx terminating TLS on the public port, plaintext to Xray
//     behind it) that ALSO carries an entry with forceTls=tls is dropped, although the
//     client speaks TLS end to end and a node would work. Note the "also": offload with
//     NO External Proxy advertises its own plaintext port, where dropping is correct. The
//     alert only lies when offload, a promoting entry AND a Clash subscriber coincide.
//   - An entry with forceTls=none on a TLS inbound still gets a node, which then
//     handshakes TLS against a plaintext endpoint and cannot connect.
//
// Gating on stream["security"] fixes both. It is not done here because the raw sub is
// already correct in both directions (genAnytlsLink resolves forceTls per endpoint the
// way genTrojanLink does), so the gap is confined to this builder and the browser
// predicate below, and those two have to land together.
//
// For whoever picks it up: anytlsClashDropReason()'s pinned cases encode SINGLE-INBOUND
// semantics (ws+reality reports the transport, tcp+reality names REALITY, tcp+none names
// TLS). Per-endpoint evaluation changes what "the reason" MEANS once two entries fail
// differently, so those assertions will not pass automatically, and passing them would
// not prove the rewrite correct either. The shape both sides agreed on: warn only when NO
// entry would yield a node, iterating entries instead of reading the inbound, with the
// reason derived from the set rather than from one configuration.
//
// MIRRORED IN THE BROWSER: anytlsClashDropReason() in web/html/modals/inbound_modal.html
// predicts these two early returns to warn the operator at edit time, and names WHICH
// reason applied. It cannot see this file. If a case here is added, removed or loosened
// (mihomo shipping AnyTLS-over-REALITY is the likely one), that predicate goes stale and
// starts confidently reporting a drop that did not happen, or missing one that did.
// That is worse than the silence it was built to fix. Change the two together.
func (s *SubClashService) buildAnytlsProxy(inbound *model.Inbound, client model.Client, extraRemark string) map[string]any {
	var rawStream map[string]any
	_ = json.Unmarshal([]byte(inbound.StreamSettings), &rawStream)

	if security, _ := rawStream["security"].(string); security != "tls" {
		return nil
	}
	if network, _ := rawStream["network"].(string); network != "" && network != "tcp" {
		return nil
	}

	proxy := map[string]any{
		"name":     s.SubService.genRemark(inbound, client.Email, extraRemark),
		"type":     "anytls",
		"server":   inbound.Listen,
		"port":     inbound.Port,
		"password": client.Password,
		"udp":      true,
	}
	applyAlwaysOnTLS(proxy, rawStream)
	return proxy
}

// buildTuicProxy produces a mihomo Clash entry for a TUIC inbound.
//
// `alpn` is pinned to h3 instead of copied from tlsSettings. The server forces h3 while
// mihomo defaults to an EMPTY ALPN list, so anything else fails the handshake with
// nothing but "no application protocol" to go on.
func (s *SubClashService) buildTuicProxy(inbound *model.Inbound, client model.Client, extraRemark string) map[string]any {
	var inboundSettings map[string]any
	_ = json.Unmarshal([]byte(inbound.Settings), &inboundSettings)

	congestion, _ := inboundSettings["congestionControl"].(string)
	if congestion == "" {
		congestion = "cubic"
	}

	proxy := map[string]any{
		"name":                  s.SubService.genRemark(inbound, client.Email, extraRemark),
		"type":                  "tuic",
		"server":                inbound.Listen,
		"port":                  inbound.Port,
		"uuid":                  client.ID,
		"password":              client.Password,
		"udp":                   true,
		"congestion-controller": congestion,
		"udp-relay-mode":        "native",
	}

	var rawStream map[string]any
	_ = json.Unmarshal([]byte(inbound.StreamSettings), &rawStream)
	applyAlwaysOnTLS(proxy, rawStream)
	proxy["alpn"] = []string{"h3"}

	// The panel stores whole seconds; mihomo's heartbeat-interval is milliseconds.
	if heartbeat, ok := inboundSettings["heartbeat"].(float64); ok && heartbeat > 0 {
		proxy["heartbeat-interval"] = int(heartbeat) * 1000
	}
	if zeroRtt, ok := inboundSettings["zeroRttHandshake"].(bool); ok && zeroRtt {
		proxy["reduce-rtt"] = true
	}
	return proxy
}

// applyAlwaysOnTLS fills in the mihomo TLS fields for the protocols whose TLS is not
// optional (hysteria, anytls, tuic). It reads inbound.StreamSettings raw rather than the
// streamData()-pruned map, because that helper drops exactly the fields wanted here
// (allowInsecure, the client fingerprint).
func applyAlwaysOnTLS(proxy map[string]any, rawStream map[string]any) {
	tlsSettings, ok := rawStream["tlsSettings"].(map[string]any)
	if !ok {
		return
	}
	if serverName, ok := tlsSettings["serverName"].(string); ok && serverName != "" {
		proxy["sni"] = serverName
	}
	if alpnList, ok := tlsSettings["alpn"].([]any); ok && len(alpnList) > 0 {
		out := make([]string, 0, len(alpnList))
		for _, a := range alpnList {
			if s, ok := a.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			proxy["alpn"] = out
		}
	}
	if inner, ok := tlsSettings["settings"].(map[string]any); ok {
		if insecure, ok := inner["allowInsecure"].(bool); ok && insecure {
			proxy["skip-cert-verify"] = true
		}
		if fp, ok := inner["fingerprint"].(string); ok && fp != "" {
			proxy["client-fingerprint"] = fp
		}
	}
}

func (s *SubClashService) applyTransport(proxy map[string]any, network string, stream map[string]any) bool {
	switch network {
	case "", "tcp":
		proxy["network"] = "tcp"
		tcp, _ := stream["tcpSettings"].(map[string]any)
		if tcp != nil {
			header, _ := tcp["header"].(map[string]any)
			if header != nil {
				typeStr, _ := header["type"].(string)
				if typeStr != "" && typeStr != "none" {
					return false
				}
			}
		}
		return true
	case "ws":
		proxy["network"] = "ws"
		ws, _ := stream["wsSettings"].(map[string]any)
		wsOpts := map[string]any{}
		if ws != nil {
			if path, ok := ws["path"].(string); ok && path != "" {
				wsOpts["path"] = path
			}
			host := ""
			if v, ok := ws["host"].(string); ok && v != "" {
				host = v
			} else if headers, ok := ws["headers"].(map[string]any); ok {
				host = searchHost(headers)
			}
			if host != "" {
				wsOpts["headers"] = map[string]any{"Host": host}
			}
		}
		if len(wsOpts) > 0 {
			proxy["ws-opts"] = wsOpts
		}
		return true
	case "grpc":
		proxy["network"] = "grpc"
		grpc, _ := stream["grpcSettings"].(map[string]any)
		grpcOpts := map[string]any{}
		if grpc != nil {
			if serviceName, ok := grpc["serviceName"].(string); ok && serviceName != "" {
				grpcOpts["grpc-service-name"] = serviceName
			}
		}
		if len(grpcOpts) > 0 {
			proxy["grpc-opts"] = grpcOpts
		}
		return true
	default:
		return false
	}
}

func (s *SubClashService) applySecurity(proxy map[string]any, security string, stream map[string]any) bool {
	switch security {
	case "", "none":
		proxy["tls"] = false
		return true
	case "tls":
		proxy["tls"] = true
		tlsSettings, _ := stream["tlsSettings"].(map[string]any)
		if tlsSettings != nil {
			if serverName, ok := tlsSettings["serverName"].(string); ok && serverName != "" {
				proxy["servername"] = serverName
				switch proxy["type"] {
				case "trojan":
					proxy["sni"] = serverName
				}
			}
			if fingerprint, ok := tlsSettings["fingerprint"].(string); ok && fingerprint != "" {
				proxy["client-fingerprint"] = fingerprint
			}
		}
		return true
	case "reality":
		proxy["tls"] = true
		realitySettings, _ := stream["realitySettings"].(map[string]any)
		if realitySettings == nil {
			return false
		}
		if serverName, ok := realitySettings["serverName"].(string); ok && serverName != "" {
			proxy["servername"] = serverName
		}
		realityOpts := map[string]any{}
		if publicKey, ok := realitySettings["publicKey"].(string); ok && publicKey != "" {
			realityOpts["public-key"] = publicKey
		}
		if shortID, ok := realitySettings["shortId"].(string); ok && shortID != "" {
			realityOpts["short-id"] = shortID
		}
		if len(realityOpts) > 0 {
			proxy["reality-opts"] = realityOpts
		}
		if fingerprint, ok := realitySettings["fingerprint"].(string); ok && fingerprint != "" {
			proxy["client-fingerprint"] = fingerprint
		}
		return true
	default:
		return false
	}
}

func (s *SubClashService) streamData(stream string) map[string]any {
	var streamSettings map[string]any
	json.Unmarshal([]byte(stream), &streamSettings)
	security, _ := streamSettings["security"].(string)
	switch security {
	case "tls":
		if tlsSettings, ok := streamSettings["tlsSettings"].(map[string]any); ok {
			streamSettings["tlsSettings"] = s.tlsData(tlsSettings)
		}
	case "reality":
		if realitySettings, ok := streamSettings["realitySettings"].(map[string]any); ok {
			streamSettings["realitySettings"] = s.realityData(realitySettings)
		}
	}
	delete(streamSettings, "sockopt")
	return streamSettings
}

func (s *SubClashService) tlsData(tData map[string]any) map[string]any {
	tlsData := make(map[string]any, 1)
	tlsClientSettings, _ := tData["settings"].(map[string]any)
	tlsData["serverName"] = tData["serverName"]
	tlsData["alpn"] = tData["alpn"]
	if fingerprint, ok := tlsClientSettings["fingerprint"].(string); ok {
		tlsData["fingerprint"] = fingerprint
	}
	return tlsData
}

func (s *SubClashService) realityData(rData map[string]any) map[string]any {
	rDataOut := make(map[string]any, 1)
	realityClientSettings, _ := rData["settings"].(map[string]any)
	if publicKey, ok := realityClientSettings["publicKey"].(string); ok {
		rDataOut["publicKey"] = publicKey
	}
	if fingerprint, ok := realityClientSettings["fingerprint"].(string); ok {
		rDataOut["fingerprint"] = fingerprint
	}
	if serverNames, ok := rData["serverNames"].([]any); ok && len(serverNames) > 0 {
		rDataOut["serverName"] = fmt.Sprint(serverNames[0])
	}
	if shortIDs, ok := rData["shortIds"].([]any); ok && len(shortIDs) > 0 {
		rDataOut["shortId"] = fmt.Sprint(shortIDs[0])
	}
	return rDataOut
}

func cloneMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
