package service

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/hasan1808/pro-ui/database"
	"github.com/hasan1808/pro-ui/database/model"
	"github.com/hasan1808/pro-ui/util/common"
)

// Port conflicts are settled here, before the inbound row is written.
//
// The failure this prevents is a quiet one. An inbound whose port is already taken
// saves without complaint and then never comes up: Xray refuses the whole config, or
// a VPN daemon exits with "address already in use" into a log nobody opens. The panel
// still lists the inbound, still shows the port, still says the protocol is there. So
// every port an inbound is going to bind is checked against the three things that can
// already hold it — another inbound, the panel itself, or some unrelated process on
// the host — and a clash is reported as an error on save instead.

// portClaim is one socket an inbound will try to open. Label names it in an error
// message when a protocol binds more than one port, and is empty for the main port.
type portClaim struct {
	port    int
	network string // "tcp" or "udp"
	label   string
}

func (c portClaim) describe() string {
	if c.label == "" {
		return strconv.Itoa(c.port)
	}
	return strconv.Itoa(c.port) + " (" + c.label + ")"
}

// inboundPortClaims returns the host sockets the inbound will actually bind.
//
// An empty result means "cannot tell", and the callers read it that way rather than
// as "nothing to check". Refusing a save wrongly blocks work the operator is entitled
// to do; missing a conflict only leaves things exactly as they were. So the protocols
// whose real listening port is not the one in the row are deliberately absent:
//
//   - GRE is IP protocol 47. It binds no port at all; the number in the row exists
//     only to key the inbound tag (see NormalizeGrePort).
//   - L2TP, PPTP and IKEv2 run one SHARED daemon each on a fixed standard port
//     (1701, 1723, 500/4500). The per-inbound port is bookkeeping, and probing it
//     would mostly rediscover the panel's own charon or xl2tpd.
func inboundPortClaims(inbound *model.Inbound) []portClaim {
	if inbound == nil || inbound.Port < 1 || inbound.Port > 65535 {
		return nil
	}

	switch inbound.Protocol {
	case model.GRE, model.L2TP, model.PPTP, model.IKEV2:
		return nil

	case model.OPENVPN:
		// Two instances, and either can be switched off. With separatePorts unset the
		// TCP one shares inbound.Port, which is legal: they are different transports.
		var st struct {
			UdpEnable     *bool `json:"udpEnable"`
			TcpEnable     *bool `json:"tcpEnable"`
			TcpPort       int   `json:"tcpPort"`
			SeparatePorts *bool `json:"separatePorts"`
		}
		if err := json.Unmarshal([]byte(inbound.Settings), &st); err != nil {
			return nil
		}
		on := func(b *bool) bool { return b == nil || *b }
		var claims []portClaim
		if on(st.UdpEnable) {
			claims = append(claims, portClaim{port: inbound.Port, network: "udp", label: "UDP"})
		}
		if on(st.TcpEnable) {
			tcpPort := inbound.Port
			// nil is the legacy shape and means separate, matching tcpListenPort.
			if st.SeparatePorts == nil || *st.SeparatePorts {
				tcpPort = st.TcpPort
			}
			if tcpPort >= 1 && tcpPort <= 65535 {
				claims = append(claims, portClaim{port: tcpPort, network: "tcp", label: "TCP"})
			}
		}
		return claims

	case model.WGC, model.AWG, model.WireGuard, model.TUIC, model.Hysteria, model.Hysteria2:
		return []portClaim{{port: inbound.Port, network: "udp"}}

	case model.OPENCONNECT, model.SSTP, model.MTPROTO, model.SSH, model.ANYTLS, model.NAIVE:
		return []portClaim{{port: inbound.Port, network: "tcp"}}
	}

	// Xray-native. The transport decides the socket family: mKCP and QUIC are
	// datagram transports, everything else Xray offers here rides TCP.
	network := "tcp"
	if inbound.StreamSettings != "" {
		var ss struct {
			Network string `json:"network"`
		}
		if err := json.Unmarshal([]byte(inbound.StreamSettings), &ss); err == nil {
			switch strings.ToLower(strings.TrimSpace(ss.Network)) {
			case "kcp", "mkcp", "quic":
				network = "udp"
			}
		}
	}
	return []portClaim{{port: inbound.Port, network: network}}
}

// checkPortConflicts refuses an inbound whose ports cannot actually be bound.
//
// ignoreId is the row being updated (0 when adding), so an inbound never conflicts
// with itself.
func (s *InboundService) checkPortConflicts(inbound *model.Inbound, ignoreId int) error {
	claims := inboundPortClaims(inbound)
	if len(claims) == 0 {
		return nil
	}

	if err := s.checkPortsAgainstInbounds(inbound, claims, ignoreId); err != nil {
		return err
	}
	if err := checkPortsAgainstPanel(claims); err != nil {
		return err
	}
	return s.checkPortsAgainstHost(inbound, claims, ignoreId)
}

// checkPortsAgainstInbounds catches the clash the DB can see. It exists alongside
// checkPortExist rather than replacing it because it also covers OpenVPN's second
// port, which lives in the settings JSON where a `port = ?` query cannot reach it.
func (s *InboundService) checkPortsAgainstInbounds(inbound *model.Inbound, claims []portClaim, ignoreId int) error {
	db := database.GetDB()
	if db == nil {
		return nil
	}
	var others []*model.Inbound
	q := db.Model(model.Inbound{})
	if ignoreId > 0 {
		q = q.Where("id != ?", ignoreId)
	}
	if err := q.Find(&others).Error; err != nil {
		return err
	}

	for _, other := range others {
		// Two inbounds on different addresses can share a port, which is the same
		// allowance checkPortExist makes.
		if !listenOverlaps(inbound.Listen, other.Listen) {
			continue
		}
		for _, oc := range inboundPortClaims(other) {
			for _, c := range claims {
				if c.port != oc.port || c.network != oc.network {
					continue
				}
				return common.NewErrorf("Port %s is already used by inbound #%d (%s)",
					c.describe(), other.Id, inboundLabel(other))
			}
		}
	}
	return nil
}

// checkPortsAgainstPanel keeps an inbound off the ports the panel serves itself on.
// Taking the web port is the expensive mistake: whichever process wins the bind, the
// operator loses the panel they would use to undo it.
func checkPortsAgainstPanel(claims []portClaim) error {
	settingService := SettingService{}

	reserved := make(map[int]string, 2)
	if webPort, err := settingService.GetPort(); err == nil && webPort > 0 {
		reserved[webPort] = "the panel"
	}
	if subEnabled, err := settingService.GetSubEnable(); err == nil && subEnabled {
		if subPort, err := settingService.GetSubPort(); err == nil && subPort > 0 {
			// The panel wins a tie: an operator serving subscriptions on the web port
			// has already made that choice.
			if _, taken := reserved[subPort]; !taken {
				reserved[subPort] = "the subscription server"
			}
		}
	}

	for _, c := range claims {
		// Both panel listeners are HTTP, so only a TCP claim can collide with them.
		if c.network != "tcp" {
			continue
		}
		if who, ok := reserved[c.port]; ok {
			return common.NewErrorf("Port %s is served by %s — pick another port", c.describe(), who)
		}
	}
	return nil
}

// checkPortsAgainstHost is the only check that can see a process the panel does not
// manage: a distro sshd, a web server, another panel. It binds the port for an
// instant and lets go.
//
// Ports the inbound already holds are skipped, or editing anything else about a
// running inbound would fail on its own listener.
func (s *InboundService) checkPortsAgainstHost(inbound *model.Inbound, claims []portClaim, ignoreId int) error {
	// A disabled inbound binds nothing, so nothing it names can conflict yet.
	if !inbound.Enable {
		return nil
	}

	held := make(map[portClaim]bool)
	if ignoreId > 0 {
		if old, err := s.GetInbound(ignoreId); err == nil && old != nil && old.Enable {
			for _, c := range inboundPortClaims(old) {
				held[portClaim{port: c.port, network: c.network}] = true
			}
		}
	}

	host := probeHost(inbound.Listen)
	for _, c := range claims {
		if held[portClaim{port: c.port, network: c.network}] {
			continue
		}
		if inUse, by := portInUse(c.network, host, c.port); inUse {
			return common.NewErrorf("Port %s is already in use on this server%s", c.describe(), by)
		}
	}
	return nil
}

// portInUse reports whether the socket is already taken, and never guesses. Anything
// other than a plain "address in use" (no permission to bind a low port, an address
// the host does not have) is not an answer, so it is treated as no conflict and the
// save proceeds.
func portInUse(network, host string, port int) (bool, string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var err error
	switch network {
	case "udp":
		var pc net.PacketConn
		pc, err = net.ListenPacket("udp", addr)
		if err == nil {
			pc.Close()
		}
	default:
		var ln net.Listener
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
		}
	}
	if err == nil {
		return false, ""
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true, " (" + strings.ToUpper(network) + ")"
	}
	return false, ""
}

// probeHost picks the address to test. A wildcard listen has to be probed as a
// wildcard: a bind of 0.0.0.0:P fails when anything holds P on any single address,
// which is exactly the conflict the inbound would hit.
func probeHost(listen string) string {
	listen = strings.TrimSpace(listen)
	switch listen {
	case "", "0.0.0.0", "::", "::0":
		return ""
	}
	return listen
}

// listenIsWildcard reports whether a Listen value names every address on the host
// rather than one of them. Blank is the form the inbound form produces ("Leave blank
// to listen on all IPs"), the rest are the explicit spellings of the same thing.
func listenIsWildcard(listen string) bool {
	switch strings.TrimSpace(listen) {
	case "", "0.0.0.0", "::", "::0":
		return true
	}
	return false
}

// listenOverlaps reports whether two inbounds would compete for the same port. A
// wildcard on either side covers every address, so it collides with anything.
func listenOverlaps(a, b string) bool {
	if listenIsWildcard(a) || listenIsWildcard(b) {
		return true
	}
	return strings.TrimSpace(a) == strings.TrimSpace(b)
}

// inboundLabel names an inbound in an error the operator has to act on: the remark
// they gave it, or the protocol when they gave it none.
func inboundLabel(inbound *model.Inbound) string {
	if remark := strings.TrimSpace(inbound.Remark); remark != "" {
		return remark
	}
	return string(inbound.Protocol)
}
