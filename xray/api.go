// Package xray provides integration with the Xray proxy core.
// It includes API client functionality, configuration management, traffic monitoring,
// and process control for Xray instances.
package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"

	"github.com/xtls/xray-core/app/proxyman/command"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	hysteriaAccount "github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// XrayAPI is a gRPC client for managing Xray core configuration, inbounds, outbounds, and statistics.
type XrayAPI struct {
	HandlerServiceClient *command.HandlerServiceClient
	StatsServiceClient   *statsService.StatsServiceClient
	grpcClient           *grpc.ClientConn
	isConnected          bool
}

func getRequiredUserString(user map[string]any, key string) (string, error) {
	value, ok := user[key]
	if !ok || value == nil {
		return "", fmt.Errorf("missing required user field %q", key)
	}

	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for user field %q: %T", key, value)
	}

	return strValue, nil
}

func getOptionalUserString(user map[string]any, key string) (string, error) {
	value, ok := user[key]
	if !ok || value == nil {
		return "", nil
	}

	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("invalid type for user field %q: %T", key, value)
	}

	return strValue, nil
}

// Init connects to the Xray API server and initializes handler and stats service clients.
func (x *XrayAPI) Init(apiPort int) error {
	if apiPort <= 0 || apiPort > math.MaxUint16 {
		return fmt.Errorf("invalid Xray API port: %d", apiPort)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to Xray API: %w", err)
	}

	x.grpcClient = conn
	x.isConnected = true

	hsClient := command.NewHandlerServiceClient(conn)
	ssClient := statsService.NewStatsServiceClient(conn)

	x.HandlerServiceClient = &hsClient
	x.StatsServiceClient = &ssClient

	return nil
}

// Close closes the gRPC connection and resets the XrayAPI client state.
func (x *XrayAPI) Close() {
	if x.grpcClient != nil {
		x.grpcClient.Close()
	}
	x.HandlerServiceClient = nil
	x.StatsServiceClient = nil
	x.isConnected = false
}

// AddInbound adds a new inbound configuration to the Xray core via gRPC.
func (x *XrayAPI) AddInbound(inbound []byte) error {
	// Init is allowed to fail (Xray not running, API port 0, dial refused) and
	// every caller in web/service ignores that error, so this can be reached with
	// no client at all. Dereferencing a nil *HandlerServiceClient here does not
	// return an error, it panics, and it panics on the request goroutine: the
	// whole PANEL process dies. That is reachable in the exact situation an
	// operator is most likely to be clicking around in, namely a core that
	// refused its config and is not up. Report it instead.
	if x.HandlerServiceClient == nil {
		return fmt.Errorf("xray api is not connected")
	}
	client := *x.HandlerServiceClient

	conf := new(conf.InboundDetourConfig)
	err := json.Unmarshal(inbound, conf)
	if err != nil {
		logger.Debug("Failed to unmarshal inbound:", err)
		return err
	}
	config, err := conf.Build()
	if err != nil {
		logger.Debug("Failed to build inbound Detur:", err)
		return err
	}
	inboundConfig := command.AddInboundRequest{Inbound: config}

	_, err = client.AddInbound(context.Background(), &inboundConfig)

	return err
}

// DelInbound removes an inbound configuration from the Xray core by tag.
func (x *XrayAPI) DelInbound(tag string) error {
	if x.HandlerServiceClient == nil {
		return fmt.Errorf("xray api is not connected")
	}
	client := *x.HandlerServiceClient
	_, err := client.RemoveInbound(context.Background(), &command.RemoveInboundRequest{
		Tag: tag,
	})
	return err
}

// Proto FULL NAMES of the account messages carried by anytls/tuic/naive. These are the
// type URLs the running core resolves through serial.GetInstance, so they must match the
// `package` + `message` of the core's own .proto byte for byte. See forkAccount.
const (
	anytlsAccountType = "xray.proxy.anytls.Account"
	tuicAccountType   = "xray.proxy.tuic.Account"
	naiveAccountType  = "xray.proxy.naive.Account"
)

// Field numbers in xray.proxy.naive.Account. Named because they are the one part of
// this encoder that fails SILENTLY when it drifts (a renumbered field lands in
// unknownFields and the account authenticates with an empty value), and naming them
// lets TestNaiveAccountFieldNumbersMatchTheCore read the core's generated tags and
// compare, rather than a human having to notice.
const (
	naiveAccountPasswordField = 1
	naiveAccountUsernameField = 2
)

type protoStringField struct {
	number int
	value  string
}

// forkAccount builds the same *serial.TypedMessage that serial.ToTypedMessage would,
// for an account message the panel cannot import.
//
// anytls/tuic/naive live only in the PATCHED core (third_party/Xray-core), which the
// panel does not link: go.mod pins the published github.com/xtls/xray-core and the fork
// is compiled separately into the embedded xray binary. So there is no
// proxy/anytls.Account type to hand to serial.ToTypedMessage the way vmess/trojan do,
// and the message has to be encoded here.
//
// That is safe because a TypedMessage is only a type URL plus the message's proto3
// bytes, and all three of these accounts are strings and nothing else. Neither half
// fails to compile if the core moves, so it is worth knowing how each one breaks:
//
//   - A renamed proto package is LOUD. AddUserOperation.ApplyInbound calls
//     User.ToMemoryUser, which resolves the type URL through the proto registry and
//     returns "failed to parse user" for a name it does not know, so AlterInbound
//     surfaces a gRPC error.
//   - A RENUMBERED field is silent. proto.Unmarshal files an unrecognised field number
//     under unknownFields and leaves the credential at its zero value, so the account
//     is accepted with an empty password and simply never authenticates.
//
// Change these in lockstep with the core's .proto.
func forkAccount(messageType string, fields ...protoStringField) *serial.TypedMessage {
	var value []byte
	for _, f := range fields {
		value = appendProtoStringField(value, f.number, f.value)
	}
	return &serial.TypedMessage{Type: messageType, Value: value}
}

// appendProtoStringField appends one proto3 string field: a varint tag of
// (number<<3 | 2 /* length-delimited */), a varint byte count, then the bytes. An empty
// value is skipped, which is exactly what protoc-gen-go emits for a proto3 scalar
// sitting at its zero value.
func appendProtoStringField(buf []byte, number int, value string) []byte {
	if value == "" {
		return buf
	}
	buf = appendProtoVarint(buf, uint64(number)<<3|2)
	buf = appendProtoVarint(buf, uint64(len(value)))
	return append(buf, value...)
}

func appendProtoVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

// AddUser adds a user to an inbound in the Xray core using the specified protocol and user data.
func (x *XrayAPI) AddUser(Protocol string, inboundTag string, user map[string]any) error {
	if x.HandlerServiceClient == nil {
		return fmt.Errorf("xray api is not connected")
	}
	userEmail, err := getRequiredUserString(user, "email")
	if err != nil {
		return err
	}

	var account *serial.TypedMessage
	switch Protocol {
	case "vmess":
		userID, err := getRequiredUserString(user, "id")
		if err != nil {
			return err
		}

		account = serial.ToTypedMessage(&vmess.Account{
			Id: userID,
		})
	case "vless":
		userID, err := getRequiredUserString(user, "id")
		if err != nil {
			return err
		}

		userFlow, err := getOptionalUserString(user, "flow")
		if err != nil {
			return err
		}

		vlessAccount := &vless.Account{
			Id:   userID,
			Flow: userFlow,
		}
		// Add testseed if provided
		if testseedVal, ok := user["testseed"]; ok {
			if testseedArr, ok := testseedVal.([]any); ok && len(testseedArr) >= 4 {
				testseed := make([]uint32, len(testseedArr))
				for i, v := range testseedArr {
					if num, ok := v.(float64); ok {
						testseed[i] = uint32(num)
					}
				}
				vlessAccount.Testseed = testseed
			} else if testseedArr, ok := testseedVal.([]uint32); ok && len(testseedArr) >= 4 {
				vlessAccount.Testseed = testseedArr
			}
		}
		// Add testpre if provided (for outbound, but can be in user for compatibility)
		if testpreVal, ok := user["testpre"]; ok {
			if testpre, ok := testpreVal.(float64); ok && testpre > 0 {
				vlessAccount.Testpre = uint32(testpre)
			} else if testpre, ok := testpreVal.(uint32); ok && testpre > 0 {
				vlessAccount.Testpre = testpre
			}
		}
		account = serial.ToTypedMessage(vlessAccount)
	case "trojan":
		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}

		account = serial.ToTypedMessage(&trojan.Account{
			Password: password,
		})
	case "shadowsocks":
		cipher, err := getOptionalUserString(user, "cipher")
		if err != nil {
			return err
		}

		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}

		var ssCipherType shadowsocks.CipherType
		switch cipher {
		case "chacha20-poly1305", "chacha20-ietf-poly1305":
			ssCipherType = shadowsocks.CipherType_CHACHA20_POLY1305
		case "xchacha20-poly1305", "xchacha20-ietf-poly1305":
			ssCipherType = shadowsocks.CipherType_XCHACHA20_POLY1305
		default:
			ssCipherType = shadowsocks.CipherType_NONE
		}

		if ssCipherType != shadowsocks.CipherType_NONE {
			account = serial.ToTypedMessage(&shadowsocks.Account{
				Password:   password,
				CipherType: ssCipherType,
			})
		} else {
			account = serial.ToTypedMessage(&shadowsocks_2022.ServerConfig{
				Key:   password,
				Email: userEmail,
			})
		}
	case "hysteria", "hysteria2":
		auth, err := getRequiredUserString(user, "auth")
		if err != nil {
			return err
		}

		account = serial.ToTypedMessage(&hysteriaAccount.Account{
			Auth: auth,
		})
	case "anytls":
		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}

		account = forkAccount(anytlsAccountType, protoStringField{1, password})
	case "tuic":
		userID, err := getRequiredUserString(user, "id")
		if err != nil {
			return err
		}

		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}

		account = forkAccount(tuicAccountType,
			protoStringField{1, userID},
			protoStringField{2, password},
		)
	case "naive":
		password, err := getRequiredUserString(user, "password")
		if err != nil {
			return err
		}

		// Optional, and the empty case is not a degenerate one: the core falls back to
		// protocol.User.Email, which is what every account created before naive had a
		// username field authenticates with. appendProtoStringField skips an empty
		// value, so the wire bytes for such an account are byte-identical to what this
		// emitted before the field existed.
		username, err := getOptionalUserString(user, "username")
		if err != nil {
			return err
		}

		account = forkAccount(naiveAccountType,
			protoStringField{naiveAccountPasswordField, password},
			protoStringField{naiveAccountUsernameField, username},
		)
	default:
		return nil
	}

	client := *x.HandlerServiceClient

	_, err = client.AlterInbound(context.Background(), &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email:   userEmail,
				Account: account,
			},
		}),
	})
	return err
}

// RemoveUser removes a user from an inbound in the Xray core by email.
func (x *XrayAPI) RemoveUser(inboundTag, email string) error {
	if x.HandlerServiceClient == nil {
		return fmt.Errorf("xray api is not connected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	op := &command.RemoveUserOperation{Email: email}
	req := &command.AlterInboundRequest{
		Tag:       inboundTag,
		Operation: serial.ToTypedMessage(op),
	}

	_, err := (*x.HandlerServiceClient).AlterInbound(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to remove user: %w", err)
	}

	return nil
}

// GetTraffic queries traffic statistics from the Xray core, optionally resetting counters.
func (x *XrayAPI) GetTraffic(reset bool) ([]*Traffic, []*ClientTraffic, error) {
	if x.grpcClient == nil {
		return nil, nil, common.NewError("xray api is not initialized")
	}

	clientTrafficRegex := regexp.MustCompile(`user>>>([^>]+)>>>traffic>>>(downlink|uplink)`)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	if x.StatsServiceClient == nil {
		return nil, nil, common.NewError("xray StatusServiceClient is not initialized")
	}

	resp, err := (*x.StatsServiceClient).QueryStats(ctx, &statsService.QueryStatsRequest{Reset_: reset})
	if err != nil {
		logger.Debug("Failed to query Xray stats:", err)
		return nil, nil, err
	}

	tagTrafficMap := make(map[string]*Traffic)
	emailTrafficMap := make(map[string]*ClientTraffic)

	for _, stat := range resp.GetStat() {
		if matches := trafficStatRegex.FindStringSubmatch(stat.Name); len(matches) == 4 {
			processTraffic(matches, stat.Value, tagTrafficMap)
		} else if matches := clientTrafficRegex.FindStringSubmatch(stat.Name); len(matches) == 3 {
			processClientTraffic(matches, stat.Value, emailTrafficMap)
		}
	}
	return mapToSlice(tagTrafficMap), mapToSlice(emailTrafficMap), nil
}

// trafficStatRegex splits an Xray traffic stat name into direction, tag and link.
// Package level so the parser and its tests cannot drift apart.
var trafficStatRegex = regexp.MustCompile(`(inbound|outbound)>>>([^>]+)>>>traffic>>>(downlink|uplink)`)

// processTraffic aggregates a traffic stat into trafficMap using regex matches and value.
func processTraffic(matches []string, value int64, trafficMap map[string]*Traffic) {
	isInbound := matches[1] == "inbound"
	tag := matches[2]
	isDown := matches[3] == "downlink"

	if tag == "api" {
		return
	}

	// Keyed by DIRECTION and tag, not by tag alone. Nothing stops an inbound and an
	// outbound sharing a name (the panel's uniqueness check spans outbounds and
	// tunnels, not inbounds), and one key for both meant the first stat the map
	// iteration happened to reach decided the direction for the pair while their bytes
	// were summed into a single record: an inbound's traffic then appeared in the
	// outbounds table, or a tunnel's egress was billed to an inbound.
	key := matches[1] + ">>>" + tag

	traffic, ok := trafficMap[key]
	if !ok {
		traffic = &Traffic{
			IsInbound:  isInbound,
			IsOutbound: !isInbound,
			Tag:        tag,
		}
		trafficMap[key] = traffic
	}

	if isDown {
		traffic.Down = value
	} else {
		traffic.Up = value
	}
}

// processClientTraffic updates clientTrafficMap with upload/download values for a client email.
func processClientTraffic(matches []string, value int64, clientTrafficMap map[string]*ClientTraffic) {
	email := matches[1]
	isDown := matches[2] == "downlink"

	traffic, ok := clientTrafficMap[email]
	if !ok {
		traffic = &ClientTraffic{Email: email}
		clientTrafficMap[email] = traffic
	}

	if isDown {
		traffic.Down = value
	} else {
		traffic.Up = value
	}
}

// mapToSlice converts a map of pointers to a slice of pointers.
func mapToSlice[T any](m map[string]*T) []*T {
	result := make([]*T, 0, len(m))
	for _, v := range m {
		result = append(result, v)
	}
	return result
}
