package sub

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/util/random"
	"github.com/mhsanaei/3x-ui/v2/web/service"
)

//go:embed default.json
var defaultJson string

// SubJsonService handles JSON subscription configuration generation and management.
type SubJsonService struct {
	configJson       map[string]any
	defaultOutbounds []json_util.RawMessage
	fragmentOrNoises bool
	mux              string

	inboundService service.InboundService
	SubService     *SubService
}

// NewSubJsonService creates a new JSON subscription service with the given configuration.
func NewSubJsonService(fragment string, noises string, mux string, rules string, subService *SubService) *SubJsonService {
	var configJson map[string]any
	var defaultOutbounds []json_util.RawMessage
	json.Unmarshal([]byte(defaultJson), &configJson)
	if outboundSlices, ok := configJson["outbounds"].([]any); ok {
		for _, defaultOutbound := range outboundSlices {
			jsonBytes, _ := json.Marshal(defaultOutbound)
			defaultOutbounds = append(defaultOutbounds, jsonBytes)
		}
	}

	fragmentOrNoises := false
	if fragment != "" || noises != "" {
		fragmentOrNoises = true
		defaultOutboundsSettings := map[string]interface{}{
			"domainStrategy": "UseIP",
			"redirect":       "",
		}

		if fragment != "" {
			defaultOutboundsSettings["fragment"] = json_util.RawMessage(fragment)
		}

		if noises != "" {
			defaultOutboundsSettings["noises"] = json_util.RawMessage(noises)
		}

		defaultDirectOutbound := map[string]interface{}{
			"protocol": "freedom",
			"settings": defaultOutboundsSettings,
			"tag":      "direct_out",
		}
		jsonBytes, _ := json.MarshalIndent(defaultDirectOutbound, "", "  ")
		defaultOutbounds = append(defaultOutbounds, jsonBytes)
	}

	if rules != "" {
		var newRules []any
		routing, _ := configJson["routing"].(map[string]any)
		defaultRules, _ := routing["rules"].([]any)
		json.Unmarshal([]byte(rules), &newRules)
		defaultRules = append(newRules, defaultRules...)
		routing["rules"] = defaultRules
		configJson["routing"] = routing
	}

	return &SubJsonService{
		configJson:       configJson,
		defaultOutbounds: defaultOutbounds,
		fragmentOrNoises: fragmentOrNoises,
		mux:              mux,
		SubService:       subService,
	}
}

// forResponse mirrors SubService.forResponse. The controller builds one
// SubJsonService at start-up and shares it across requests, so the per-response
// scope has to live on a copy, and the copy has to be the one getConfig sees since
// that is where the node names are composed.
func (s *SubJsonService) forResponse() *SubJsonService {
	scoped := *s
	scoped.SubService = s.SubService.forResponse()
	return &scoped
}

// GetJson generates a JSON subscription configuration for the given subscription ID and host.
func (s *SubJsonService) GetJson(subId string, host string) (string, string, error) {
	s = s.forResponse()
	inbounds, err := s.SubService.getInboundsBySubId(subId)
	if err != nil || len(inbounds) == 0 {
		return "", "", err
	}

	var header string
	usage := newSubUsage()
	var configArray []json_util.RawMessage

	// Prepare Inbounds
	for _, inbound := range inbounds {
		clients, err := s.inboundService.GetClients(inbound)
		if err != nil {
			logger.Error("SubJsonService - GetClients: Unable to get clients from inbound")
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
				newConfigs := s.getConfig(inbound, client, host)
				configArray = append(configArray, newConfigs...)
			}
		}
	}

	if len(configArray) == 0 {
		return "", "", nil
	}

	// Prepare statistics. Folded per identity, so an account served on several
	// inbounds reports its own quota once instead of collapsing to unlimited; see
	// subUsage.
	traffic := usage.result()

	// Combile outbounds
	var finalJson []byte
	if len(configArray) == 1 {
		finalJson, _ = json.MarshalIndent(configArray[0], "", "  ")
	} else {
		finalJson, _ = json.MarshalIndent(configArray, "", "  ")
	}

	header = fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", traffic.Up, traffic.Down, traffic.Total, traffic.ExpiryTime/1000)
	return string(finalJson), header, nil
}

func (s *SubJsonService) getConfig(inbound *model.Inbound, client model.Client, host string) []json_util.RawMessage {
	// The Xray-JSON sub can only carry protocols Xray-core has an outbound for. The new
	// protocols (mtproto/ssh/wg-c/awg/gre + the credential VPNs) have no such outbound, so
	// they are delivered via the raw and Clash subs and skipped here rather than emitting
	// a JSON config with no working outbound.
	//
	// anytls and tuic DO have one, but only in the patched core this panel ships: a
	// subscriber running stock Xray gets "unknown config id" for that one profile. Each
	// element of the array is a standalone config, so the blast radius is that profile
	// alone. naive stays out because it has no Xray outbound at all.
	switch inbound.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria", "hysteria2", "anytls", "tuic":
	default:
		return nil
	}
	var newJsonArray []json_util.RawMessage
	stream := s.streamData(inbound.StreamSettings)

	externalProxies, ok := stream["externalProxy"].([]any)
	if !ok || len(externalProxies) == 0 {
		externalProxies = []any{
			map[string]any{
				"forceTls": "same",
				"dest":     host,
				"port":     float64(inbound.Port),
				"remark":   "",
			},
		}
	}

	delete(stream, "externalProxy")

	for _, ep := range externalProxies {
		extPrxy := ep.(map[string]any)
		inbound.Listen = extPrxy["dest"].(string)
		inbound.Port = int(extPrxy["port"].(float64))
		newStream := stream
		switch extPrxy["forceTls"].(string) {
		case "tls":
			if newStream["security"] != "tls" {
				newStream["security"] = "tls"
				newStream["tlsSettings"] = map[string]any{}
			}
		case "none":
			if newStream["security"] != "none" {
				newStream["security"] = "none"
				delete(newStream, "tlsSettings")
			}
		}
		streamSettings, _ := json.MarshalIndent(newStream, "", "  ")

		var newOutbounds []json_util.RawMessage

		switch inbound.Protocol {
		case "vmess":
			newOutbounds = append(newOutbounds, s.genVnext(inbound, streamSettings, client))
		case "vless":
			newOutbounds = append(newOutbounds, s.genVless(inbound, streamSettings, client))
		// anytls joins trojan/shadowsocks: its account is a bare password and its
		// outbound reads the same `servers` array, so genServer already emits it
		// correctly. (The core's infra/conf must accept that shape.)
		case "trojan", "shadowsocks", "anytls":
			newOutbounds = append(newOutbounds, s.genServer(inbound, streamSettings, client))
		case "hysteria", "hysteria2":
			newOutbounds = append(newOutbounds, s.genHy(inbound, newStream, client))
		case "tuic":
			newOutbounds = append(newOutbounds, s.genTuic(inbound, newStream, client))
		}

		newOutbounds = append(newOutbounds, s.defaultOutbounds...)
		newConfigJson := make(map[string]any)
		maps.Copy(newConfigJson, s.configJson)

		newConfigJson["outbounds"] = newOutbounds
		newConfigJson["remarks"] = s.SubService.genRemark(inbound, client.Email, extPrxy["remark"].(string))

		newConfig, _ := json.MarshalIndent(newConfigJson, "", "  ")
		newJsonArray = append(newJsonArray, newConfig)
	}

	return newJsonArray
}

func (s *SubJsonService) streamData(stream string) map[string]any {
	var streamSettings map[string]any
	json.Unmarshal([]byte(stream), &streamSettings)
	security, _ := streamSettings["security"].(string)
	switch security {
	case "tls":
		streamSettings["tlsSettings"] = s.tlsData(streamSettings["tlsSettings"].(map[string]any))
	case "reality":
		streamSettings["realitySettings"] = s.realityData(streamSettings["realitySettings"].(map[string]any))
	}
	delete(streamSettings, "sockopt")

	if s.fragmentOrNoises {
		streamSettings["sockopt"] = json_util.RawMessage(`{"dialerProxy": "direct_out", "tcpKeepAliveIdle": 100}`)
	}

	// remove proxy protocol
	network, _ := streamSettings["network"].(string)
	switch network {
	case "tcp":
		streamSettings["tcpSettings"] = s.removeAcceptProxy(streamSettings["tcpSettings"])
	case "ws":
		streamSettings["wsSettings"] = s.removeAcceptProxy(streamSettings["wsSettings"])
	case "httpupgrade":
		streamSettings["httpupgradeSettings"] = s.removeAcceptProxy(streamSettings["httpupgradeSettings"])
	}
	return streamSettings
}

func (s *SubJsonService) removeAcceptProxy(setting any) map[string]any {
	netSettings, ok := setting.(map[string]any)
	if ok {
		delete(netSettings, "acceptProxyProtocol")
	}
	return netSettings
}

func (s *SubJsonService) tlsData(tData map[string]any) map[string]any {
	tlsData := make(map[string]any, 1)
	tlsClientSettings, _ := tData["settings"].(map[string]any)

	tlsData["serverName"] = tData["serverName"]
	tlsData["alpn"] = tData["alpn"]
	if fingerprint, ok := tlsClientSettings["fingerprint"].(string); ok {
		tlsData["fingerprint"] = fingerprint
	}
	return tlsData
}

func (s *SubJsonService) realityData(rData map[string]any) map[string]any {
	rltyData := make(map[string]any, 1)
	rltyClientSettings, _ := rData["settings"].(map[string]any)

	rltyData["show"] = false
	rltyData["publicKey"] = rltyClientSettings["publicKey"]
	rltyData["fingerprint"] = rltyClientSettings["fingerprint"]
	rltyData["mldsa65Verify"] = rltyClientSettings["mldsa65Verify"]

	// Set random data
	rltyData["spiderX"] = "/" + random.Seq(15)
	shortIds, ok := rData["shortIds"].([]any)
	if ok && len(shortIds) > 0 {
		rltyData["shortId"] = shortIds[random.Num(len(shortIds))].(string)
	} else {
		rltyData["shortId"] = ""
	}
	serverNames, ok := rData["serverNames"].([]any)
	if ok && len(serverNames) > 0 {
		rltyData["serverName"] = serverNames[random.Num(len(serverNames))].(string)
	} else {
		rltyData["serverName"] = ""
	}

	return rltyData
}

func (s *SubJsonService) genVnext(inbound *model.Inbound, streamSettings json_util.RawMessage, client model.Client) json_util.RawMessage {
	outbound := Outbound{}
	usersData := make([]UserVnext, 1)

	usersData[0].ID = client.ID
	usersData[0].Email = client.Email
	usersData[0].Security = client.Security
	vnextData := make([]VnextSetting, 1)
	vnextData[0] = VnextSetting{
		Address: inbound.Listen,
		Port:    inbound.Port,
		Users:   usersData,
	}

	outbound.Protocol = string(inbound.Protocol)
	outbound.Tag = "proxy"
	if s.mux != "" {
		outbound.Mux = json_util.RawMessage(s.mux)
	}
	outbound.StreamSettings = streamSettings
	outbound.Settings = map[string]any{
		"vnext": vnextData,
	}

	result, _ := json.MarshalIndent(outbound, "", "  ")
	return result
}

func (s *SubJsonService) genVless(inbound *model.Inbound, streamSettings json_util.RawMessage, client model.Client) json_util.RawMessage {
	outbound := Outbound{}
	outbound.Protocol = string(inbound.Protocol)
	outbound.Tag = "proxy"
	if s.mux != "" {
		outbound.Mux = json_util.RawMessage(s.mux)
	}
	outbound.StreamSettings = streamSettings

	// Add encryption for VLESS outbound from inbound settings
	var inboundSettings map[string]any
	json.Unmarshal([]byte(inbound.Settings), &inboundSettings)
	encryption, _ := inboundSettings["encryption"].(string)

	user := map[string]any{
		"id":         client.ID,
		"level":      8,
		"encryption": encryption,
	}
	if client.Flow != "" {
		user["flow"] = client.Flow
	}

	vnext := map[string]any{
		"address": inbound.Listen,
		"port":    inbound.Port,
		"users":   []any{user},
	}

	outbound.Settings = map[string]any{
		"vnext": []any{vnext},
	}
	result, _ := json.MarshalIndent(outbound, "", "  ")
	return result
}

func (s *SubJsonService) genServer(inbound *model.Inbound, streamSettings json_util.RawMessage, client model.Client) json_util.RawMessage {
	outbound := Outbound{}

	serverData := make([]ServerSetting, 1)
	serverData[0] = ServerSetting{
		Address:  inbound.Listen,
		Port:     inbound.Port,
		Level:    8,
		Password: client.Password,
	}

	if inbound.Protocol == model.Shadowsocks {
		var inboundSettings map[string]any
		json.Unmarshal([]byte(inbound.Settings), &inboundSettings)
		method, _ := inboundSettings["method"].(string)
		serverData[0].Method = method

		// server password in multi-user 2022 protocols
		if strings.HasPrefix(method, "2022") {
			if serverPassword, ok := inboundSettings["password"].(string); ok {
				serverData[0].Password = fmt.Sprintf("%s:%s", serverPassword, client.Password)
			}
		}
	}

	outbound.Protocol = string(inbound.Protocol)
	outbound.Tag = "proxy"
	if s.mux != "" {
		outbound.Mux = json_util.RawMessage(s.mux)
	}
	outbound.StreamSettings = streamSettings
	outbound.Settings = map[string]any{
		"servers": serverData,
	}

	result, _ := json.MarshalIndent(outbound, "", "  ")
	return result
}

// genTuic builds the Xray-JSON outbound for a TUIC account. It does not go through
// genServer because a TUIC account is a uuid AND a password, and the outbound's
// congestion control has to match the server's or the two disagree on the QUIC
// algorithm. The transport name is likewise fixed: the core selects its QUIC transport
// off `network: tuic`, and TLS is not optional.
func (s *SubJsonService) genTuic(inbound *model.Inbound, newStream map[string]any, client model.Client) json_util.RawMessage {
	outbound := Outbound{}

	outbound.Protocol = string(inbound.Protocol)
	outbound.Tag = "proxy"
	if s.mux != "" {
		outbound.Mux = json_util.RawMessage(s.mux)
	}

	var settings map[string]any
	json.Unmarshal([]byte(inbound.Settings), &settings)
	congestionControl, _ := settings["congestionControl"].(string)
	if congestionControl == "" {
		congestionControl = "cubic"
	}

	outbound.Settings = map[string]any{
		"servers": []map[string]any{{
			"address":  inbound.Listen,
			"port":     inbound.Port,
			"level":    8,
			"email":    client.Email,
			"id":       client.ID,
			"password": client.Password,
		}},
		"congestionControl": congestionControl,
		"udpRelayMode":      "native",
	}

	newStream["network"] = "tuic"
	newStream["security"] = "tls"
	outbound.StreamSettings, _ = json.MarshalIndent(newStream, "", "  ")

	result, _ := json.MarshalIndent(outbound, "", "  ")
	return result
}

func (s *SubJsonService) genHy(inbound *model.Inbound, newStream map[string]any, client model.Client) json_util.RawMessage {
	outbound := Outbound{}

	outbound.Protocol = string(inbound.Protocol)
	outbound.Tag = "proxy"

	if s.mux != "" {
		outbound.Mux = json_util.RawMessage(s.mux)
	}

	var settings, stream map[string]any
	json.Unmarshal([]byte(inbound.Settings), &settings)
	version, _ := settings["version"].(float64)
	outbound.Settings = map[string]any{
		"version": int(version),
		"address": inbound.Listen,
		"port":    inbound.Port,
	}

	json.Unmarshal([]byte(inbound.StreamSettings), &stream)
	hyStream := stream["hysteriaSettings"].(map[string]any)
	outHyStream := map[string]any{
		"version": int(version),
		"auth":    client.Auth,
	}
	if udpIdleTimeout, ok := hyStream["udpIdleTimeout"].(float64); ok {
		outHyStream["udpIdleTimeout"] = int(udpIdleTimeout)
	}
	newStream["hysteriaSettings"] = outHyStream

	if finalmask, ok := hyStream["finalmask"].(map[string]any); ok {
		newStream["finalmask"] = finalmask
	}

	newStream["network"] = "hysteria"
	newStream["security"] = "tls"

	outbound.StreamSettings, _ = json.MarshalIndent(newStream, "", "  ")

	result, _ := json.MarshalIndent(outbound, "", "  ")
	return result
}

type Outbound struct {
	Protocol       string               `json:"protocol"`
	Tag            string               `json:"tag"`
	StreamSettings json_util.RawMessage `json:"streamSettings"`
	Mux            json_util.RawMessage `json:"mux,omitempty"`
	Settings       map[string]any       `json:"settings,omitempty"`
}

type VnextSetting struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []UserVnext `json:"users"`
}

type UserVnext struct {
	ID       string `json:"id"`
	Email    string `json:"email,omitempty"`
	Security string `json:"security,omitempty"`
}

type ServerSetting struct {
	Password string `json:"password"`
	Level    int    `json:"level"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Flow     string `json:"flow,omitempty"`
	Method   string `json:"method,omitempty"`
}
